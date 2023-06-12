import datetime
import tempfile
import unittest

import freezegun

from misp_feed_generator import main
from misp_feed_generator.utils import set_default_config, validated_config


class TestSimulation(unittest.TestCase):
    config = validated_config(
        set_default_config(
            {
                "crowdsec_lapi_url": "http://localhost:8080/",
                "crowdsec_lapi_key": "e2725120ba9a23f82b6d2f651426dab6",
                "crowdsec_update_frequency": "10s",
                "misp_feed_reset_frequency": "1w",
                "misp_feed_orgc": {
                    "name": "CrowdSec",
                    "uuid": "5f6e7b5a-6b1a-4c0e-8a3c-9b9c5a474e8c",
                },
                "misp_feed_threat_level_id": 1,
                "misp_feed_published": True,
                "misp_feed_tags": [],
                "log_level": "info",
                "log_mode": "stdout",
                "log_file": "/var/log/crowdsec-misp-feed.log",
                "output_dir": "",
                "listen_addr": "0.0.0.0",
                "listen_port": 2450,
                "tls": {"enabled": False, "cert_file": "", "key_file": ""},
                "basic_auth": {
                    "enabled": True,
                    "username": "admin",
                    "password": "secret",
                },
            }
        )
    )

    def setUp(self) -> None:
        main.event_by_scenario_and_origin.clear()
        return super().setUp()

    def test_initial_creation(self):
        lapi_data = {
            "new": [
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/thinkphp-cve-2018-20062",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "157.208.36.100",
                },
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/thinkphp-cve-2018-20062",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "1.2.3.4",
                },
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788023,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/thinkphp-cve-2018-20062",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "157.208.36.100",
                },
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "test/test",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "157.208.36.100",
                },
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "cscli",
                    "scenario": "test/test",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "157.208.36.100",
                },
            ],
            "deleted": [
                {
                    "duration": "-151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "event_for_this_should_not_exist",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "8.8.8.8",
                },
            ],
        }
        self.config["output_dir"] = tempfile.mkdtemp(prefix="initial_creation_")
        with freezegun.freeze_time("2023-07-05 00:00:00"):
            main.last_time_manage_feed_called = datetime.datetime.now()
            main.manage_feeds(self.config, lapi_data)

        self.assertEqual(len(main.event_by_scenario_and_origin), 3)

        for decision in lapi_data["new"]:
            key = main.decision_to_key(decision)
            self.assertIn(key, main.event_by_scenario_and_origin)

            # assert an IP exists in the event for this decision and it's not repeated
            found = False
            for object in main.event_by_scenario_and_origin[key]["Event"]["Object"]:
                if object["Attribute"][0]["value"] == decision["value"]:
                    if found:
                        self.fail("IP is repeated in event")
                    found = True
            self.assertTrue(found)

        for decision in lapi_data["deleted"]:
            key = main.decision_to_key(decision)
            self.assertNotIn(key, main.event_by_scenario_and_origin)

    def test_create_delete_create(self):
        lapi_data = {
            "new": [
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/thinkphp-cve-2018-20062",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "1.2.3.4",
                },
            ],
            "deleted": [],
        }
        self.config["output_dir"] = tempfile.mkdtemp(prefix="deletion_")
        with freezegun.freeze_time("2023-07-05 00:00:00"):
            main.last_time_manage_feed_called = datetime.datetime.now()
            main.manage_feeds(self.config, lapi_data)
        self.assertEqual(len(main.event_by_scenario_and_origin), 1)
        self.assertEqual(
            len(
                main.event_by_scenario_and_origin[
                    main.decision_to_key(lapi_data["new"][0])
                ]["Event"]["Object"]
            ),
            1,
        )
        self.assertFalse(
            main.event_by_scenario_and_origin[
                main.decision_to_key(lapi_data["new"][0])
            ]["Event"]["Object"][0]["deleted"]
        )
        self.assertFalse(
            main.event_by_scenario_and_origin[
                main.decision_to_key(lapi_data["new"][0])
            ]["Event"]["Object"][0]["Attribute"][0]["deleted"]
        )

        lapi_data = {
            "new": [],
            "deleted": [
                {
                    "duration": "-151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/thinkphp-cve-2018-20062",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "1.2.3.4",
                },
            ],
        }
        with freezegun.freeze_time("2023-07-05 00:00:00"):
            main.last_time_manage_feed_called = datetime.datetime.now()
            main.manage_feeds(self.config, lapi_data)
        self.assertEqual(len(main.event_by_scenario_and_origin), 1)
        self.assertEqual(
            len(
                main.event_by_scenario_and_origin[
                    main.decision_to_key(lapi_data["deleted"][0])
                ]["Event"]["Object"]
            ),
            1,
        )
        self.assertTrue(
            main.event_by_scenario_and_origin[
                main.decision_to_key(lapi_data["deleted"][0])
            ]["Event"]["Object"][0]["deleted"]
        )
        self.assertTrue(
            main.event_by_scenario_and_origin[
                main.decision_to_key(lapi_data["deleted"][0])
            ]["Event"]["Object"][0]["Attribute"][0]["deleted"]
        )

        lapi_data = {
            "new": [
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/thinkphp-cve-2018-20062",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "1.2.3.4",
                },
            ],
            "deleted": [],
        }
        with freezegun.freeze_time("2023-07-05 00:00:00"):
            main.last_time_manage_feed_called = datetime.datetime.now()
            main.manage_feeds(self.config, lapi_data)
        self.assertEqual(len(main.event_by_scenario_and_origin), 1)
        self.assertEqual(
            len(
                main.event_by_scenario_and_origin[
                    main.decision_to_key(lapi_data["new"][0])
                ]["Event"]["Object"]
            ),
            1,
        )
        self.assertFalse(
            main.event_by_scenario_and_origin[
                main.decision_to_key(lapi_data["new"][0])
            ]["Event"]["Object"][0]["deleted"]
        )
        self.assertFalse(
            main.event_by_scenario_and_origin[
                main.decision_to_key(lapi_data["new"][0])
            ]["Event"]["Object"][0]["Attribute"][0]["deleted"]
        )

    def test_update_last_seen(self):
        lapi_data = {
            "new": [
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/thinkphp-cve-2018-20062",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "1.2.3.4",
                },
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "test/test",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "1.2.3.4",
                },
            ],
            "deleted": [],
        }
        self.config["output_dir"] = tempfile.mkdtemp(prefix="update_last_seen_")

        with freezegun.freeze_time("2023-07-05 00:00:00"):
            main.last_time_manage_feed_called = datetime.datetime.now()
            main.manage_feeds(self.config, lapi_data)
            for decision in lapi_data["new"]:
                key = main.decision_to_key(decision)
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["date"],
                    "2023-07-05",
                )
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                        "first_seen"
                    ],
                    "2023-07-05T00:00:00",
                )
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                        "last_seen"
                    ],
                    "2023-07-05T00:00:00",
                )
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                        "Attribute"
                    ][0]["first_seen"],
                    "2023-07-05T00:00:00",
                )
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                        "Attribute"
                    ][0]["last_seen"],
                    "2023-07-05T00:00:00",
                )

        lapi_data = {
            "deleted": [
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "test/test",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "1.2.3.4",
                },
            ],
            "new": [
                {
                    "duration": "151h39m35.023794714s",
                    "id": 3788022,
                    "origin": "CAPI",
                    "scenario": "crowdsecurity/thinkphp-cve-2018-20062",
                    "scope": "Ip",
                    "type": "ban",
                    "value": "1.2.3.4",
                },
            ],
        }

        with freezegun.freeze_time("2023-07-06 00:00:00"):
            main.last_time_manage_feed_called = datetime.datetime.now()
            main.manage_feeds(self.config, lapi_data)
            for decision in lapi_data["new"]:
                # Only the last seen should be updated
                key = main.decision_to_key(decision)
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["date"],
                    "2023-07-05",
                )
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                        "first_seen"
                    ],
                    "2023-07-05T00:00:00",
                )
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                        "last_seen"
                    ],
                    "2023-07-06T00:00:00",
                )
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                        "Attribute"
                    ][0]["first_seen"],
                    "2023-07-05T00:00:00",
                )
                self.assertEqual(
                    main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                        "Attribute"
                    ][0]["last_seen"],
                    "2023-07-06T00:00:00",
                )

    def test_feed_reset(self):
        self.config["output_dir"] = tempfile.mkdtemp(prefix="feed_reset")
        with freezegun.freeze_time("2023-07-05 00:00:00"):
            time_first = datetime.datetime.now()
            main.last_time_manage_feed_called = time_first
            lapi_data = {
                "new": [
                    {
                        "duration": "151h39m35.023794714s",
                        "id": 3788022,
                        "origin": "CAPI",
                        "scenario": "crowdsecurity/thinkphp-cve-2018-20062",
                        "scope": "Ip",
                        "type": "ban",
                        "value": "1.2.3.4",
                    },
                ],
                "deleted": [],
            }
            decision = lapi_data["new"][0]
            key = main.decision_to_key(decision)
            main.manage_feeds(self.config, lapi_data)
            self.assertEqual(len(main.event_by_scenario_and_origin), 1)
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["info"],
                f"{decision['scenario']}-{decision['origin']}-{time_first.isoformat().split('.')[0]}",
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["date"], "2023-07-05"
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                    "first_seen"
                ],
                "2023-07-05T00:00:00",
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                    "last_seen"
                ],
                "2023-07-05T00:00:00",
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                    "Attribute"
                ][0]["first_seen"],
                "2023-07-05T00:00:00",
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                    "Attribute"
                ][0]["last_seen"],
                "2023-07-05T00:00:00",
            )

        with freezegun.freeze_time("2023-07-13 00:00:00"):
            main.last_time_manage_feed_called = time_first
            main.manage_feeds(self.config, lapi_data)
            time_now = datetime.datetime.now()
            self.assertEqual(len(main.event_by_scenario_and_origin), 1)
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["info"],
                f"{decision['scenario']}-{decision['origin']}-{time_now.isoformat().split('.')[0]}",
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["date"], "2023-07-13"
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                    "first_seen"
                ],
                "2023-07-05T00:00:00",
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                    "last_seen"
                ],
                "2023-07-13T00:00:00",
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                    "Attribute"
                ][0]["first_seen"],
                "2023-07-05T00:00:00",
            )
            self.assertEqual(
                main.event_by_scenario_and_origin[key]["Event"]["Object"][0][
                    "Attribute"
                ][0]["last_seen"],
                "2023-07-13T00:00:00",
            )


if __name__ == "__main__":
    unittest.main()
