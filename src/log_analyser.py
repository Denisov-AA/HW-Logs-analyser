# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import argparse
import gzip
import json
import logging
import os
import re
from collections import OrderedDict, namedtuple
from datetime import date, datetime
from os import PathLike
from string import Template
from typing import Generator

parser = argparse.ArgumentParser(description="Log analyzer")
parser.add_argument("--config", dest="config_path")

log_line_re_dict = dict(
    REMOTE_ADDR=r"\S+",
    REMOTE_USER=r"\S+",
    HTTP_X_REAL_IP=r"\S+",
    TIME_LOCAL=r"\[.*\]",
    URL=r'"(\S+\s)?(?P<url>\S+)(\s\S+)?"',
    STATUS=r"\d{3}",
    BODY_BYTES_SENT=r"\d+",
    HTTP_REFERER=r'".+"',
    HTTP_USER_AGENT=r'".+"',
    HTTP_X_FORWARDED_FOR=r'".+"',
    HTTP_X_REQUEST_ID=r'".+"',
    HTTP_X_RB_USER=r'".+"',
    REQUEST_TIME=r"(?P<request_time>.*?)",
    S=r"\s+",
)

LOG_LINE_REGEX = (
    r"^{REMOTE_ADDR}{S}{REMOTE_USER}{S}{HTTP_X_REAL_IP}{S}{TIME_LOCAL}{S}{URL}{S}{STATUS}{S}"
    + r"{BODY_BYTES_SENT}{S}{HTTP_REFERER}{S}{HTTP_USER_AGENT}{S}{HTTP_X_FORWARDED_FOR}{S}"
    + r"{HTTP_X_REQUEST_ID}{S}{HTTP_X_RB_USER}{S}{REQUEST_TIME}$"
).format(**log_line_re_dict)

CONFIG_DIR = "../config"

REPORT_FILE_TEMPLATE = r"report-%Y.%m.%d.html"

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "../reports",
    "LOG_DIR": "../log",
    "TEMPLATE": "../reports/report.html",
    "MAX_ERROR_RATE": 0.8,
    "LOG_FILE": "log_analyzer.log",
    "LOG_LEVEL": "DEBUG",
}

LatestLog = namedtuple("LatestLog", "path ext max_date")
RequestData = namedtuple("RequestData", "urls time_total count_total")


def find_latest_log(app_config: dict) -> LatestLog:
    """
    Find latest log file and check if it's already analyzed

    :param dict app_config: Log analyzer configuration
    :return: Path to log file, log file extension, latest log date
    :rtype: namedtuple of (path, ext, max_date)
    """
    max_date = date.min
    log_path = log_ext = ""
    for filename in os.listdir(app_config["LOG_DIR"]):
        match = re.match(
            r"^nginx-access-ui\.log-(?P<request_date>\d{8})(?P<ext>(\.gz)?)$", filename
        )
        if not match:
            continue

        ext = match.group("ext")

        try:
            cur_date = datetime.strptime(match.group("request_date"), "%Y%m%d").date()
        except ValueError:
            logging.error(f"Incorrect date: {match.group('request_date')}")
            continue

        if cur_date > max_date:
            max_date = cur_date
            log_path = filename
            log_ext = ext

    if not log_path or log_ext not in ["", ".gz"]:
        logging.info("No log file detected")
    elif log_path:
        logging.info(f"Found log: {log_path}")

    return LatestLog(log_path, log_ext, max_date)


def parse(app_config: dict, latest_log: LatestLog) -> Generator:
    """
    Iterate log file and yield parsed url and request_time

    :param app_config: Log analyzer configuration
    :param latest_log: LatestLog namedtuple
    :return: None if got a parse error, (url, request_time) otherwise
    """
    openfunc = gzip.open if latest_log.ext == ".gz" else open
    with openfunc(
        os.path.join(app_config["LOG_DIR"], latest_log.path), "rt", encoding="utf-8"
    ) as fp:
        for line in fp:
            match = re.search(LOG_LINE_REGEX, line)
            if match:
                url = match.group("url")
                request_time = float(match.group("request_time"))
                yield url, request_time
            else:
                yield


def read_config(config_path: str | PathLike):
    """
    Read config file if exists and merge with the default config

    :param config_path: Path to config file
    :return: Log analyzer configuration if config file exists None otherwise
    """

    try:
        with open(config_path, "r", encoding="utf-8") as fp:
            # Merge configs (config from file has a priority)
            return {**config, **json.load(fp)}
    except IOError as error:
        logging.error(f"Can't read config file {config_path}. {error}")


def read_template():
    """
    Reads template into a str

    :return: Template str if file exists, None otherwise
    """
    try:
        with open(config["TEMPLATE"], "r", encoding="utf-8") as fp:
            return fp.read()
    except IOError as error:
        logging.error(f"Could not read template file: {config['TEMPLATE']}. {error}")


def collect_request_data(app_config, latest_log, parse_func):
    """
    Collects parsed request data (number of requests, urls, request time)

    :param app_config: config dict
    :param latest_log: LatestLog namedtuple
    :param parse_func: log parser
    :return: RequestData (dict of urls, total request time, total number of requests) if parsing is ok, None otherwise
    """
    urls = {}
    count_total = 0
    time_total = 0

    num_errors = 0
    num_lines = 0

    for row in parse_func(app_config, latest_log):

        num_lines += 1

        if not row:
            num_errors += 1
            continue

        url, request_time = row

        time_total += request_time
        count_total += 1
        if url in urls:
            urls[url]["count"] += 1
            urls[url]["time"].append(request_time)
            urls[url]["time_sum"] += request_time
        else:
            urls[url] = {"count": 1, "time": [request_time], "time_sum": request_time}

    if num_errors / num_lines > app_config["MAX_ERROR_RATE"]:
        logging.error(f"Maximum error rate reached in {latest_log.path}")
        return

    urls = OrderedDict(
        sorted(
            urls.items(), key=lambda key_value: key_value[1]["time_sum"], reverse=True
        )[: app_config["REPORT_SIZE"]]
    )

    return RequestData(urls, time_total, count_total)


def calc_stats(request_data):
    """
    :param request_data: namedtuple of (urls, time_total, count_total)
    :return: JS-ready statistics for the HTML template
    """

    table_json = []
    for url, value in request_data.urls.items():
        sorted_time = sorted(value["time"])
        len_time = len(sorted_time)
        half_len_time = len_time // 2
        table_json.append(
            {
                "url": url,
                "count": value["count"],
                "count_perc": round(value["count"] / request_data.count_total, 6),
                "time_sum": round(value["time_sum"], 4),
                "time_perc": round(value["time_sum"] / request_data.time_total, 6),
                "time_avg": round(value["time_sum"] / len_time, 4),
                "time_max": round(sorted_time[-1], 4),
                "time_med": (
                    round(sorted_time[half_len_time], 4)
                    if len_time % 2
                    else round(
                        (sorted_time[half_len_time] + sorted_time[half_len_time - 1])
                        / 2.0,
                        4,
                    )
                ),
            }
        )
    return table_json


def create_report(report_dir, report_path, template_path, table_json):
    """
    Renders template and writes an HTML report file

    :param report_dir: report directory
    :param report_path: report path
    :param template_path: template path
    :param table_json: JSON stats table
    """

    try:
        with open(template_path, "r", encoding="utf-8") as fp:
            template = fp.read()
    except IOError as error:
        logging.error(f"Can't read template file: {template_path}. {error}")
        return

    try:
        if not os.path.isdir(report_dir):
            os.mkdir(report_dir)

        with open(report_path, "w", encoding="utf-8") as f_out:
            f_out.write(
                Template(template).safe_substitute(table_json=json.dumps(table_json))
            )
            logging.info(f"Report successfully created: {report_path}")
    except IOError as error:
        logging.error(f"Can't write to file: {report_path}.\n{error}")


def main():
    args = parser.parse_args()
    config_path = os.path.join(
        CONFIG_DIR, args.config_path if args.config_path else "log_analyser.json"
    )

    if not (app_config := read_config(config_path)):
        raise Exception("Analyser configuration not set")

    logging.basicConfig(
        filename=app_config.get("LOG_FILE"),
        level=app_config.get("LOG_LEVEL", "DEBUG"),
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )

    latest_log = find_latest_log(app_config)
    if not latest_log.path:
        raise Exception("Log file not found")

    report_path = os.path.join(
        app_config["REPORT_DIR"], latest_log.max_date.strftime(REPORT_FILE_TEMPLATE)
    )
    if os.path.isfile(report_path):
        logging.info(f"Report for {latest_log.path} already created")
        return

    request_data = collect_request_data(app_config, latest_log, parse)

    if not request_data:
        return

    table_json = calc_stats(request_data)

    create_report(
        app_config["REPORT_DIR"], report_path, app_config["TEMPLATE"], table_json
    )


if __name__ == "__main__":
    try:
        main()
    except BaseException as e:
        logging.exception(e)
