import argparse
import datetime
import json
import os
import ssl
import sys
import time
import uuid
import hashlib
from http.server import HTTPServer, SimpleHTTPRequestHandler
from multiprocessing import Process

import requests
import yaml

from misp_feed_generator.server import AuthHTTPRequestHandler
from misp_feed_generator.utils import (
    logger,
    set_default_config,
    set_logging,
    validate_config,
)

event_by_scenario_and_origin = {}  # key: scenario_origin, value: event
last_time_manage_feed_called = datetime.datetime.now()
hashes_to_save = []


def get_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def save_hashes(config):
    global hashes_to_save
    with open(os.path.join(config["output_dir"], "hashes.csv"), "a+") as hash_file:
        for h, event_id in hashes_to_save:
            hash_file.write("{},{}\n".format(event_id, h))
    hashes_to_save = []


def update_manifest(config):
    manifest_file = os.path.join(config["output_dir"], "manifest.json")
    manifest_data = {}
    for filename in os.listdir(config["output_dir"]):
        if filename.endswith(".json") and filename != "manifest.json":
            with open(os.path.join(config["output_dir"], filename), "r") as file:
                try:
                    event = json.load(file)
                except json.decoder.JSONDecodeError:
                    logger.error(f"Could not load {filename}")
                    continue
                manifest_data[event["Event"]["uuid"]] = {
                    "Orgc": event["Event"]["Orgc"],
                    "Tag": event["Event"]["Tag"],
                    "info": event["Event"]["info"],
                    "date": event["Event"]["date"],
                    "analysis": int(event["Event"]["analysis"]),
                    "threat_level_id": int(event["Event"]["threat_level_id"]),
                    "timestamp": int(event["Event"]["timestamp"]),
                }
    with open(manifest_file, "w") as file:
        json.dump(manifest_data, file, indent=4)


def make_http_handler_from_config(config):
    if config.get("basic_auth"):
        if config["basic_auth"].get("enabled"):
            AuthHTTPRequestHandler.username = config["basic_auth"]["username"]
            AuthHTTPRequestHandler.password = config["basic_auth"]["password"]
            return AuthHTTPRequestHandler
    return SimpleHTTPRequestHandler


def serve_dir(config):
    logger.info(
        f"Serving feeds from {config['output_dir']} on {config['listen_addr']}:{config['listen_port']}"
    )
    handler = make_http_handler_from_config(config)
    httpd = HTTPServer((config["listen_addr"], int(config["listen_port"])), handler)
    if config["tls"]["enabled"]:
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            keyfile=config["tls"]["key_file"],
            certfile=config["tls"]["cert_file"],
            server_side=True,
        )
    os.chdir(config["output_dir"])
    httpd.serve_forever()


def manage_feeds(config, lapi_data):
    global last_time_manage_feed_called
    if (
        datetime.datetime.now() - last_time_manage_feed_called
        >= config["misp_feed_reset_frequency"]
    ):
        reset_feeds(lapi_data, config)
        last_time_manage_feed_called = datetime.datetime.now()

    for new_decision in lapi_data["new"]:
        key = decision_to_key(new_decision)
        if key not in event_by_scenario_and_origin:
            event_by_scenario_and_origin[key] = create_misp_event(new_decision, config)
        event = event_by_scenario_and_origin[key]
        if not ip_exists_in_event(new_decision["value"], event):
            object = create_misp_feed_object(new_decision, event["Event"]["uuid"])
            event["Event"]["Object"].append(object)
        else:
            update_object_by_ip(event, new_decision["value"], deleted=False)

    for deleted_decision in lapi_data["deleted"]:
        key = decision_to_key(deleted_decision)
        if key in event_by_scenario_and_origin:
            event = event_by_scenario_and_origin[key]
            ip = deleted_decision["value"]
            update_object_by_ip(event, ip, deleted=True)

    # Save events to files
    for _, event in event_by_scenario_and_origin.items():
        write_event_to_file(config, event)
    update_manifest(config)
    save_hashes(config)


def update_object_by_ip(event, ip, deleted):
    for obj in event["Event"]["Object"]:
        if obj["Attribute"][0]["value"] == ip:
            add_hash = False
            obj["deleted"] = deleted
            if not deleted:
                add_hash = True
                obj["last_seen"] = datetime.datetime.now().isoformat()
                obj["Attribute"][0]["last_seen"] = datetime.datetime.now().isoformat()
            if obj["Attribute"][0]["deleted"] != deleted:
                add_hash = True
                obj["Attribute"][0]["deleted"] = deleted
            if add_hash:
                hashes_to_save.append(
                    (
                        (
                            hashlib.md5(
                                json.dumps(obj["Attribute"][0], sort_keys=True).encode(
                                    "utf-8"
                                )
                            ).hexdigest(),
                            event["Event"]["uuid"],
                        ),
                        event["Event"]["uuid"],
                    )
                )


def ip_exists_in_event(ip, event):
    for existing_object in event["Event"]["Object"]:
        if existing_object["Attribute"][0]["value"] == ip:
            return True
    return False


def create_misp_event(decision, config):
    time_now = datetime.datetime.now()
    timestamp_now = int(time_now.timestamp())

    return {
        "Event": {
            "analysis": int(config["misp_feed_analysis_level"]),
            "date": datetime.date.today().isoformat(),
            "extends_uuid": "",
            "info": f"{decision['scenario']}-{decision['origin']}-{time_now.isoformat().split('.')[0]}",
            "publish_timestamp": str(timestamp_now),
            "published": config["misp_feed_published"],
            "threat_level_id": config["misp_feed_threat_level_id"],
            "timestamp": str(timestamp_now),
            "uuid": str(uuid.uuid4()),
            "Orgc": {
                "name": config["misp_feed_orgc"]["name"],
                "uuid": config["misp_feed_orgc"]["uuid"],
            },
            "Tag": config["misp_feed_tags"],
            "Object": [],
        }
    }


def decision_to_key(decision):
    return f"{decision['scenario']}_{decision['origin']}"


def create_misp_feed_object(decision, event_uuid):
    time_now = datetime.datetime.now()
    timestamp_now = int(time_now.timestamp())
    object_data = {
        "comment": "",
        "deleted": False,
        "description": "An IP address (or domain or hostname) and a port seen as a tuple (or as a triple) "
        "in a specific time frame.",
        "first_seen": time_now.isoformat(),
        "last_seen": time_now.isoformat(),
        "meta-category": "network",
        "name": "ip-port",
        "template_uuid": "9f8cea74-16fe-4968-a2b4-026676949ac6",
        "template_version": "9",
        "timestamp": str(timestamp_now),
        "uuid": str(uuid.uuid4()),
        "Attribute": [create_object_attribute_from_object(decision)],
    }
    hashes_to_save.append(
        (
            hashlib.md5(
                json.dumps(object_data["Attribute"][0], sort_keys=True).encode("utf-8")
            ).hexdigest(),
            event_uuid,
        )
    )
    return object_data


def create_object_attribute_from_object(decision):
    time_now = datetime.datetime.now()
    timestamp_now = int(time_now.timestamp())
    attribute_data = {
        "category": "Network activity",
        "comment": "",
        "deleted": False,
        "disable_correlation": False,
        "first_seen": time_now.isoformat(),
        "last_seen": time_now.isoformat(),
        "object_relation": "ip",
        "timestamp": str(timestamp_now),
        "to_ids": True,
        "type": "ip-src",
        "uuid": str(uuid.uuid4()),
        "value": decision["value"],
    }
    return attribute_data


def event_with_object(event, obj):
    event["event_data"]["Event"]["Object"].append(obj)
    return event


def write_event_to_file(config, event):
    event_uuid = event["Event"]["uuid"]
    filename = os.path.join(config["output_dir"], f"{event_uuid}.json")
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as file:
        json.dump(event, file, indent=2)


def lapi_url_from_config(config, startup=False):
    url = config["crowdsec_lapi_url"]
    if not url.endswith("/"):
        url += "/"
    url += "v1/decisions/stream?"
    if startup:
        url += "startup=true&"
    if config["include_scenarios_containing"]:
        url += (
            f"scenarios_containing={','.join(config['include_scenarios_containing'])}&"
        )
    if config["exclude_scenarios_containing"]:
        url += f"scenarios_not_containing={','.join(config['exclude_scenarios_containing'])}&"
    if config["only_include_decisions_from"]:
        url += f"origins={','.join(config['only_include_decisions_from'])}"

    return url


def fetch_lapi_data(config, startup=False):
    lapi_url = lapi_url_from_config(config, startup)
    api_key = config["crowdsec_lapi_key"]
    headers = {"X-Api-Key": api_key}

    try:
        logger.info("GET " + lapi_url)
        response = requests.get(lapi_url, headers=headers)
        response.raise_for_status()
        lapi_data = response.json()
        if not lapi_data.get("new"):
            lapi_data["new"] = []
        if not lapi_data.get("deleted"):
            lapi_data["deleted"] = []
        return lapi_data
    except requests.exceptions.RequestException as e:
        logger.error(f"Error executing request: {e}")
        return {"new": [], "deleted": []}


def reset_feeds(lapi_data, config):
    global event_by_scenario_and_origin
    new_event_by_scenario_and_origin = {}
    for new_decision in lapi_data["new"]:
        key = decision_to_key(new_decision)
        if key not in new_event_by_scenario_and_origin:
            new_event_by_scenario_and_origin[key] = create_misp_event(
                new_decision, config
            )
            if key in event_by_scenario_and_origin:
                new_event_by_scenario_and_origin[key]["Event"]["Object"] = list(
                    filter(
                        lambda obj: not obj["deleted"],
                        event_by_scenario_and_origin[key]["Event"]["Object"],
                    )
                )
            for idx, _ in enumerate(
                event_by_scenario_and_origin[key]["Event"]["Object"]
            ):
                new_event_by_scenario_and_origin[key]["Event"]["Object"][idx][
                    "last_seen"
                ] = datetime.datetime.now().isoformat()
                new_event_by_scenario_and_origin[key]["Event"]["Object"][idx][
                    "Attribute"
                ][0]["last_seen"] = datetime.datetime.now().isoformat()

    event_by_scenario_and_origin = new_event_by_scenario_and_origin


def run(config):
    set_logging(config)
    if not os.path.exists(config["output_dir"]):
        os.makedirs(config["output_dir"])
    Process(target=serve_dir, args=(config,)).start()
    first_run = True
    while True:
        try:
            lapi_data = fetch_lapi_data(config, first_run)
        except Exception as e:
            logger.error(f"Error fetching data from LAPI: {e}")
            if first_run:
                sys.exit(1)
            continue
        first_run = False
        manage_feeds(config, lapi_data)
        time.sleep(config["crowdsec_update_frequency"])


def generate_base_config():
    base_cfg = f"""
# CrowdSec Config
crowdsec_lapi_url: http://localhost:8080/
crowdsec_lapi_key: <your_lapi_key>
crowdsec_update_frequency: 1m
include_scenarios_containing: [] # ignore IPs banned for triggering scenarios not containing either of provided word, eg ["ssh", "http"]
exclude_scenarios_containing: [] # ignore IPs banned for triggering scenarios containing either of provided word
only_include_decisions_from: [] # only include IPs banned due to decisions orginating from provided sources. eg value ["cscli", "crowdsec"]

# MISP Config
misp_feed_reset_frequency: 1w
misp_event_analysis_level: 2
misp_feed_orgc:
  name: CrowdSec
  uuid: 5f6e7b5a-6b1a-4c0e-8a3c-9b9c5a474e8c

misp_feed_threat_level_id: 4
misp_feed_published: false
misp_feed_tags: []

# Bouncer Config

output_dir: ./crowdsec-misp-feed/

# Bouncer Server Config
listen_addr: 0.0.0.0
listen_port: 2450
tls:
  enabled: true
  cert_file: "cert.pem"
  key_file: "key.pem"

basic_auth:
  enabled: false
  username: ""
  password: ""

# Log Config
log_level: info
log_mode: stdout
    """
    print(base_cfg)


def main():
    parser = argparse.ArgumentParser(description="CrowdSec MISP Feed Generator")
    parser.add_argument(
        "-c", "--config", help="Path to the configuration file", default="config.yaml"
    )
    parser.add_argument(
        "-g", help="Generate base config", default=False, action="store_true"
    )
    args = parser.parse_args()
    if args.g:
        generate_base_config()
        sys.exit(0)
    config = get_config(args.config)
    config = set_default_config(config)
    validate_config(config)
    run(config)


if __name__ == "__main__":
    main()
