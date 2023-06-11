import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from pytimeparse import parse as parse_time
from datetime import timedelta


class CustomFormatter(logging.Formatter):
    FORMATS = {
        logging.ERROR: "[%(asctime)s] %(levelname)s - %(message)s",
        logging.WARNING: "[%(asctime)s] %(levelname)s - %(message)s",
        logging.DEBUG: "[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s",
        "DEFAULT": "[%(asctime)s] %(levelname)s - %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


logger = logging.getLogger("")
default_handler = logging.StreamHandler(sys.stdout)
default_formatter = CustomFormatter()
default_handler.setFormatter(default_formatter)
logger.addHandler(default_handler)
logger.setLevel(logging.INFO)


def get_log_level(log_level) -> int:
    log_level_by_str = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }
    if log_level not in log_level_by_str:
        raise ValueError(f"Invalid log level: {log_level}")
    return log_level_by_str[log_level.lower()]


def set_default_config(config):
    if not config.get("output_dir"):
        config["output_dir"] = "./crowdsec-misp-feeds"
    if not config.get("include_scenarios_containing"):
        config["include_scenarios_containing"] = []
    if not config.get("exclude_scenarios_containing"):
        config["exclude_scenarios_containing"] = []
    if not config.get("only_include_decisions_from"):
        config["only_include_decisions_from"] = []
    if not config.get("tls"):
        config["tls"] = {}
    if not config.get("log_level"):
        config["log_level"] = "info"
    if not config.get("log_mode"):
        config["log_mode"] = "stdout"
    if not config.get("log_file") and config["log_mode"] == "file":
        config["log_file"] = "/var/log/crowdsec-misp-feeds.log"
        logger.info(f"Logging to {config['log_file']}")
    if not config.get("crowdsec_update_frequency"):
        config["crowdsec_update_frequency"] = "1m"
    if not config.get("misp_feed_reset_frequency"):
        config["misp_feed_reset_frequency"] = "1w"
    if not config.get("misp_feed_threat_level_id"):
        config["misp_feed_threat_level_id"] = 4
    if not config.get("misp_feed_analysis_level"):
        config["misp_feed_analysis_level"] = 2

    return config


def validate_config(config):
    if os.path.exists(config["output_dir"]) and os.listdir(config["output_dir"]):
        logger.warning(
            f"Output directory {config['output_dir']} exists and is not empty"
        )
    if not config.get("crowdsec_lapi_url"):
        raise ValueError("crowdsec_lapi_url is not set")
    if not config.get("crowdsec_lapi_key"):
        raise ValueError("crowdsec_lapi_key is not set")
    if not config.get("misp_feed_orgc", {}).get("name"):
        raise ValueError("misp_feed_orgc.name is not set")
    if not config.get("misp_feed_orgc", {}).get("uuid"):
        raise ValueError("misp_feed_orgc.uuid is not set")

    if config.get("tls", {}).get("enabled"):
        if not config["tls"].get("cert_file"):
            raise ValueError("tls.cert_file is not set")
        if not config["tls"].get("key_file"):
            raise ValueError("tls.key_file is not set")

    if not parse_time(config["crowdsec_update_frequency"]):
        raise ValueError(
            "crowdsec_update_frequency is not a valid duration. Example: 1d, 1h, 1m, 1s"
        )

    if not parse_time(config["misp_feed_reset_frequency"]):
        raise ValueError(
            "misp_feed_reset_frequency is not a valid duration. Example: 1d, 1h, 1m, 1s"
        )

    config["misp_feed_reset_frequency"] = timedelta(
        seconds=parse_time(config["misp_feed_reset_frequency"])
    )
    config["crowdsec_update_frequency"] = timedelta(
        seconds=parse_time(config["crowdsec_update_frequency"])
    )
    return config


def set_logging(config):
    global logger
    list(map(logger.removeHandler, logger.handlers))
    logger.setLevel(get_log_level(config["log_level"]))
    if config["log_mode"] == "stdout":
        handler = logging.StreamHandler(sys.stdout)
    elif config["log_mode"] == "stderr":
        handler = logging.StreamHandler(sys.stderr)
    elif config["log_mode"] == "file":
        handler = RotatingFileHandler(config["log_file"], mode="a+")
    else:
        raise ValueError(f"Invalid log mode: {config['log_mode']}")

    formatter = CustomFormatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info(f"Starting MISP Feed Generator")
