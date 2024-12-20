import argparse
import logging
import sys
import json
from urllib import request, parse
import time
from pathlib import Path
import configparser


config = configparser.ConfigParser()
config.read(Path(__file__).resolve().parent / "config.ini")
BASEURL = config.get("Nessus", "url")
ACCESSKEY = config.get("Nessus", "accessKey")
SECRETKEY = config.get("Nessus", "secretKey")
APITOKEN = config.get("Nessus", "apiToken")

logging.basicConfig(
    level=logging.DEBUG, format="%(levelname)-8s %(funcName)s:%(lineno)d - %(message)s"
#    level=logging.INFO, format="%(levelname)-8s %(message)s"
)


def scan_list():
    url = f"{BASEURL}/scans"
    headers = { "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}" }

    data, _ = api_call(url, headers=headers, method="GET")
    data = json.loads(data.decode())

    return data["folders"], data["scans"]


def scan_details(scanid):
    url = f"{BASEURL}/scans/{scanid}"
    headers = { "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}" }

    data, _ = api_call(url, headers=headers, method="GET")
    data = json.loads(data.decode())

    return data


def scan_diff(scanid, history):
    url = f"{BASEURL}/scans/{scanid}/diff?history_id={history[1]}"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
        "X-Api-Token": f"{APITOKEN}"
    }

    params = { "diff_id": history[0] }
    params = parse.urlencode(params).encode("utf-8")

    api_call(url, headers=headers, params=params, method="POST")


def export_request(scanid, repformat, reptype, severity, history=None):
    url = f"{BASEURL}/scans/{scanid}/export"
    if history:
        url += f"?diff_id={history[0]}&history_id={history[1]}&limit=2500"

    headers = { "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}" }

    params = { "format": repformat }
    params = params | { "chapters": reptype }
    for index, value in enumerate(severity):
        match value:
            case "info":
                params = params | {
                    f"filter.{index}.quality":"eq",
                    f"filter.{index}.filter":"severity",
                    f"filter.{index}.value":"0"
                }
            case "low":
                params = params | {
                    f"filter.{index}.quality":"eq",
                    f"filter.{index}.filter":"severity",
                    f"filter.{index}.value":"1"
                }
            case "medium":
                params = params | {
                    f"filter.{index}.quality":"eq",
                    f"filter.{index}.filter":"severity",
                    f"filter.{index}.value":"2"
                }
            case "high":
                params = params | {
                    f"filter.{index}.quality":"eq",
                    f"filter.{index}.filter":"severity",
                    f"filter.{index}.value":"3"
                }
            case "critical":
                params = params | {
                    f"filter.{index}.quality":"eq",
                    f"filter.{index}.filter":"severity",
                    f"filter.{index}.value":"4"
                }
    params = params | { "filter.search_type":"or" }
    params = parse.urlencode(params).encode("utf-8")

    data, _ = api_call(url, headers=headers, params=params, method="POST")
    data = json.loads(data.decode())

    return data["token"], data["file"]


def token_status(token):
    url = f"{BASEURL}/tokens/{token}/status"
    headers = { "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}" }

    data, _ = api_call(url, headers=headers, method="GET")
    data = json.loads(data.decode())

    return data["error"], data["message"], data["status"]


def token_download(token, filepath=None, filename=None):
    url = f"{BASEURL}/tokens/{token}/download"
    reqheaders = { "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}" }

    data, resheaders = api_call(url, headers=reqheaders, method="GET")

    if filename is None:
        for header, value in resheaders:
            if header == "Content-Disposition":
                filename = value.split("filename=")[-1]
                filename = filename.strip("\"'")

    if filepath is None:
        filepath = Path(__file__).resolve().parent

    abspath = filepath / filename
    with open(abspath, "wb") as file:
        file.write(data)

    return abspath


def api_call(url, headers=None, params=None, method="GET"):
    req = request.Request(url, headers=headers, method=method, data=params)
    with request.urlopen(req) as response:
        response_data = response.read()
        response_headers = response.getheaders()
    return response_data, response_headers


def nessus_report(args):
    folders, scans = scan_list()

    # Get folder ID
    folderid = None
    for folder in folders:
        if folder["name"] == args.dir:
            folderid = folder["id"]

    if folderid is None:
        logging.error("Folder \"%s\" does not exist!", args.dir)
        sys.exit(1)

    # Get scan ID and status
    scanid = status = None
    for scan in scans:
        if scan["name"] == args.name and scan["folder_id"] == folderid:
            scanid = scan["id"]
            status = scan["status"]

    if scanid is None or status is None:
        logging.error("Scan \"%s\" does not exist!", args.name)
        sys.exit(1)

    # Check if scan is completed
    if status == "running":
        logging.error("Scan is still running!")
        sys.exit(1)

    # Creat diff, if necessary
    history = []
    if args.diff:
        details = scan_details(scanid)
        count = len(details["history"])
        if count <= 1:
            logging.error("There is only one scan history - diff not possible!")
            sys.exit()
        history.append(int(details["history"][count-1]["history_id"]))
        history.append(int(details["history"][count-2]["history_id"]))

        scan_diff(scanid, history)

    # Trigger report generation
    token, _ = export_request(scanid, args.format, args.type, args.severity, history)

    # Wait for report to be genereated
    while True:
        _ , message, status = token_status(token)
        logging.info("[%s] %s", status, message)
        if status != "loading":
            break
        time.sleep(5)

    # Download report
    if status == "ready":
        abspath = token_download(token)
        logging.info("Download finished! >> \"%s\"", abspath)
    else:
        logging.error("An error occured!")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(required=True)

    # Subparser for "report" argument
    report_parser = subparsers.add_parser("report")
    report_parser.add_argument(
        "--name",
        help="Scan name",
        required=True
    )
    report_parser.add_argument(
        "--dir",
        help="Scan directory",
        default="My Scans"
    )
    report_parser.add_argument(
        "--format",
        choices=["pdf", "csv", "nessus"],
        help="Report format",
        default="pdf"
    )
    report_parser.add_argument(
        "--type",
        choices=["vuln_hosts_summary", "vuln_by_host", "compliance_exec", "remediations", "vuln_by_plugin", "compliance"],
        help="Report type",
        default=["vuln_by_plugin"]
    )
    report_parser.add_argument(
        "--severity",
        choices=["info", "low", "medium", "high", "critical"],
        nargs="+",
        help="Specify relevant severity level(s)",
        default=["info", "low", "medium", "high", "critical"]
    )
    report_parser.add_argument(
        "--diff",
        help="Shows only the differences of the last two scans in the report",
        action="store_true",
    )
    report_parser.set_defaults(func=nessus_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
