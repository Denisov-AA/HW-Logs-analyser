import datetime
import logging
import os
import sys
import unittest

import src.log_analyser as la

CONFIG_SAMPLE = {
    "REPORT_SIZE": 2000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "TEMPLATE": "./reports/report.html",
    "MAX_ERROR_RATE": 0.8,
    "LOG_FILE": "log_analyzer.log",
    "LOG_LEVEL": "DEBUG",
}


class LogAnalyzerTest(unittest.TestCase):
    config_path = "./config/log_analyser.json"

    def test_good_config_file(self):
        sys.argv += ["--config", "config.json"]
        self.assertEqual(la.read_config(self.config_path), CONFIG_SAMPLE)

    def test_no_log_found(self):
        config = la.read_config(self.config_path)
        config["LOG_DIR"] = "./src"
        self.assertEqual(la.find_latest_log(config)[0], "")

    def test_bz2_log_handling(self):
        config = la.read_config(self.config_path)
        config["LOG_DIR"] = "./tests/bz"
        self.assertEqual(la.find_latest_log(config)[0], "")

    def test_plain_log_handling(self):
        config = la.read_config(self.config_path)
        config["LOG_DIR"] = "./tests/plain"
        self.assertEqual(
            la.find_latest_log(config),
            ("nginx-access-ui.log-20170630", "", datetime.date(2017, 6, 30)),
        )

    def test_gz_log_handling(self):
        config = la.read_config(self.config_path)
        config["LOG_DIR"] = "./log/"
        self.assertEqual(
            la.find_latest_log(config),
            la.LatestLog(
                "nginx-access-ui.log-20170630.gz", ".gz", datetime.date(2017, 6, 30)
            ),
        )

    def test_incorrect_log_data(self):
        config = la.read_config(self.config_path)
        config["LOG_DIR"] = "./tests/plain"
        logfile = "nginx-access-ui.log-20170630"
        logging.basicConfig(
            filename=config.get("LOG_FILE", None),
            filemode="w",
            level=logging.DEBUG,
            format="[%(asctime)s] %(levelname).1s %(message)s",
            datefmt="%Y.%m.%d %H:%M:%S",
            force=True
        )
        la.collect_request_data(
            config, la.LatestLog(logfile, "", datetime.date(2017, 6, 30)), la.parse
        )

        with open(config["LOG_FILE"], "r") as fp:
            self.assertIn(
                f"Maximum error rate reached in {logfile}", fp.readlines()[-1]
            )


if __name__ == "__main__":
    unittest.main()
