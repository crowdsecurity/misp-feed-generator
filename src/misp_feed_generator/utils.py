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


def validated_config(config):
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


scenario_to_behavior = {
    "Dominic-Wagner/vaultwarden-bf": "http:bruteforce",
    "LePresidente/authelia-bf": "http:bruteforce",
    "LePresidente/emby-bf": "http:bruteforce",
    "LePresidente/gitea-bf": "http:bruteforce",
    "LePresidente/ombi-bf": "http:bruteforce",
    "baudneo/gotify-bf": "http:bruteforce",
    "baudneo/zoneminder-bf": "http:bruteforce",
    "crowdsecurity/CVE-2021-4034": "http:exploit",
    "crowdsecurity/CVE-2022-41082": "http:exploit",
    "crowdsecurity/CVE-2022-37042": "http:exploit",
    "crowdsecurity/apache_log4j2_cve-2021-44228": "http:exploit",
    "crowdsecurity/asterisk_bf": "sip:bruteforce",
    "crowdsecurity/asterisk_user_enum": "sip:bruteforce",
    "crowdsecurity/cpanel-bf": "http:bruteforce",
    "crowdsecurity/cpanel-bf-attempt": "http:bruteforce",
    "timokoessler/mongodb-bf": "http:bruteforce",
    "crowdsecurity/dovecot-spam": "pop3/imap:bruteforce",
    "crowdsecurity/endlessh-bf": "ssh:bruteforce",
    "crowdsecurity/exchange-bf": "pop3/imap:bruteforce",
    "crowdsecurity/f5-big-ip-cve-2020-5902": "http:exploit",
    "crowdsecurity/fortinet-cve-2018-13379": "http:exploit",
    "crowdsecurity/grafana-cve-2021-43798": "http:exploit",
    "crowdsecurity/home-assistant-bf": "iot:bruteforce",
    "crowdsecurity/http-backdoors-attempts": "http:scan",
    "crowdsecurity/http-bad-user-agent": "http:scan",
    "crowdsecurity/http-bf-wordpress_bf": "http:bruteforce",
    "crowdsecurity/http-bf-wordpress_bf_xmlrpc": "http:bruteforce",
    "crowdsecurity/http-crawl-non_statics": "http:crawl",
    "crowdsecurity/http-cve-2021-41773": "http:exploit",
    "crowdsecurity/http-cve-2021-42013": "http:exploit",
    "crowdsecurity/http-generic-bf": "http:bruteforce",
    "crowdsecurity/http-open-proxy": "http:scan",
    "crowdsecurity/http-path-traversal-probing": "http:scan",
    "crowdsecurity/http-probing": "http:scan",
    "crowdsecurity/http-sensitive-files": "http:scan",
    "crowdsecurity/http-sqli-probing": "http:exploit",
    "crowdsecurity/http-wordpress_user-enum": "http:bruteforce",
    "crowdsecurity/http-wordpress_wpconfig": "http:bruteforce",
    "crowdsecurity/http-xss-probing": "http:exploit",
    "crowdsecurity/iptables-scan-multi_ports": "tcp:scan",
    "crowdsecurity/jira_cve-2021-26086": "http:exploit",
    "crowdsecurity/litespeed-admin-bf": "http:bruteforce",
    "crowdsecurity/mariadb-bf": "database:bruteforce",
    "crowdsecurity/modsecurity": "http:exploit",
    "crowdsecurity/mssql-bf": "database:bruteforce",
    "crowdsecurity/mysql-bf": "database:bruteforce",
    "crowdsecurity/naxsi-exploit-vpatch": "http:exploit",
    "crowdsecurity/nextcloud-bf": "http:bruteforce",
    "crowdsecurity/nginx-req-limit-exceeded": "http:crawl",
    "crowdsecurity/odoo-bf_user-enum": "http:bruteforce",
    "crowdsecurity/opensips-request": "sip:bruteforce",
    "crowdsecurity/opnsense-gui-bf": "http:bruteforce",
    "crowdsecurity/pgsql-bf": "database:bruteforce",
    "crowdsecurity/postfix-spam": "pop3/imap:bruteforce",
    "crowdsecurity/proftpd-bf": "ftp:bruteforce",
    "crowdsecurity/proftpd-bf_user-enum": "ftp:bruteforce",
    "crowdsecurity/pulse-secure-sslvpn-cve-2019-11510": "http:exploit",
    "crowdsecurity/smb-bf": "smb:bruteforce",
    "crowdsecurity/spring4shell_cve-2022-22965": "http:exploit",
    "crowdsecurity/ssh-bf": "ssh:bruteforce",
    "crowdsecurity/ssh-slow-bf": "ssh:bruteforce",
    "crowdsecurity/suricata-alerts": "generic:exploit",
    "crowdsecurity/synology-dsm-bf": "http:bruteforce",
    "crowdsecurity/telnet-bf": "telnet:bruteforce",
    "crowdsecurity/thinkphp-cve-2018-20062": "http:exploit",
    "crowdsecurity/vmware-cve-2022-22954": "http:exploit",
    "crowdsecurity/vmware-vcenter-vmsa-2021-0027": "http:exploit",
    "crowdsecurity/vsftpd-bf": "ftp:bruteforce",
    "crowdsecurity/windows-CVE-2022-30190-msdt": "generic:exploit",
    "crowdsecurity/windows-bf": "windows:bruteforce",
    "firewallservices/lemonldap-ng-bf": "ldap:bruteforce",
    "firewallservices/pf-scan-multi_ports": "tcp:scan",
    "firewallservices/zimbra-bf": "http:bruteforce",
    "fulljackz/proxmox-bf": "vm-management:bruteforce",
    "fulljackz/pureftpd-bf": "ftp:bruteforce",
    "hitech95/mail-generic-bf": "pop3/imap:bruteforce",
    "ltsich/http-w00tw00t": "http:scan",
    "thespad/sshesame-honeypot": "ssh:bruteforce",
    "timokoessler/gitlab-bf": "http:bruteforce",
    "timokoessler/uptime-kuma-bf": "http:bruteforce",
    "LePresidente/jellyseerr-bf": "http:bruteforce",
    "crowdsecurity/http-apiscp-bf": "http:bruteforce",
    "lourys/pterodactyl-wings-bf": "http:bruteforce",
    "crowdsecurity/CVE-2022-26134": "http:exploit",
    "crowdsecurity/CVE-2022-35914": "http:exploit",
    "crowdsecurity/CVE-2022-40684": "http:exploit",
    "crowdsecurity/fortinet-cve-2022-40684": "http:exploit",
    "shield/btinvalidscript": "http:scan",
    "shield/btauthorfishing": "http:scan",
    "shield/ratelimit": "http:bruteforce",
    "shield/humanspam": "http:spam",
    "shield/markspam": "http:spam",
    "shield/btxml": "http:exploit",
    "drupal/auth-bruteforce": "http:bruteforce",
    "drupal/4xx-scan": "http:scan",
    "drupal/core-ban": "http:exploit",
}
