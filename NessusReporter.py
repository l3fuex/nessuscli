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

parser = argparse.ArgumentParser()
parser.add_argument(
    "-d",
    "--dir",
    help="Folder to search for scans (defaults to \"My Scans\")",
    default="My Scans"
)
parser.add_argument(
    "-n",
    "--name",
    help="Scan to generate report from",
    required=True
)
parser.add_argument(
    "-f",
    "--format",
    choices=["pdf", "csv", "nessus"],
    help="Report format (defaults to \"pdf\")",
    default="pdf"
)
parser.add_argument(
    "-t",
    "--type",
    choices=["vuln_hosts_summary", "vuln_by_host", "compliance_exec", "remediations", "vuln_by_plugin", "compliance"],
    help="Report type (defaults to \"vuln_by_plugin\")",
    default=["vuln_by_plugin"]
)
parser.add_argument(
    "-s",
    "--severity",
    choices=["info", "low", "medium", "high", "critical"],
    nargs="+",
    help="Severity level(s) which should be included in the report",
    default=["info", "low", "medium", "high", "critical"]
)
parser.add_argument(
    "--diff",
    help="Differnce between the last two scans",
    action="store_true",
)
args = parser.parse_args()


def scan_list():
    # Build url and headers
    url = f"{BASEURL}/scans"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}"
    }

    # Send request
    req = request.Request(url, headers=headers)
    with request.urlopen(req) as response:
        data = json.loads(response.read().decode())

    return data["folders"], data["scans"]


def scan_details(scanid):
    # Build url and headers
    url = f"{BASEURL}/scans/{scanid}"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
    }

    # Send request
    req = request.Request(url, headers=headers)
    with request.urlopen(req) as response:
        data = json.loads(response.read().decode())

    return data


def scan_diff(scanid, history):
    # Build url and headers
    url = f"{BASEURL}/scans/{scanid}/diff?history_id={history[1]}"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
        "X-Api-Token": f"{APITOKEN}"
    }

    # Build post parameters
    params = { "diff_id": history[0] }
    params = parse.urlencode(params).encode("utf-8")
    print(params)

    # Send request
    req = request.Request(url, data=params, headers=headers, method="POST")
    request.urlopen(req)


def export_request(scanid, history=None):
    def build_params():
        params = { "format": args.format }
        params = params | { "chapters": args.type }
        for index, severity in enumerate(args.severity):
            match severity:
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

        return parse.urlencode(params).encode("utf-8")

    url = f"{BASEURL}/scans/{scanid}/export"
    if history:
        url += f"?diff_id={history[0]}&history_id={history[1]}&limit=2500"

    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
    }
    params = build_params()

    req = request.Request(url, data=params, headers=headers, method="POST")
    with request.urlopen(req) as response:
        data = json.loads(response.read().decode())

    return data["token"]


def tokens_status(token):
    url = f"{BASEURL}/tokens/{token}/status"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
    }

    req = request.Request(url, headers=headers)
    with request.urlopen(req) as response:
        data = json.loads(response.read().decode())

    logging.info("Status: \"%s\"", data["status"])

    return data["status"]


def tokens_download(token):
    url = f"{BASEURL}/tokens/{token}/download"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
    }

    req = request.Request(url, headers=headers)
    with request.urlopen(req) as response:

        filename = response.getheader("Content-Disposition")
        filename = filename.split("filename=")[-1].strip("\"'")
        filename = Path(__file__).resolve().parent / filename

        with open(filename, "wb") as report:
            report.write(response.read())

    logging.info("Downloading file: \"%s\"", filename)

    return filename


def get_scanid(folders, scans):
    folderid = scanid = status = None

    # Get folder ID
    for folder in folders:
        if folder["name"] == args.dir:
            folderid = folder["id"]

    if folderid is None:
        logging.error("Folder <%s> does not exist!", args.dir)
        sys.exit(1)

    # Get scan ID in specified folder
    for scan in scans:
        if scan["name"] == args.name and scan["folder_id"] == folderid:
            scanid = scan["id"]
            status = scan["status"]

    if scanid is None:
        logging.error("Scan <%s> does not exist!", args.name)
        sys.exit(1)

    logging.debug("Scan ID is: \"%s\"", scanid)

    return scanid, status


def main():
    # Get scan ID
    folders, scans = scan_list()
    scanid, scanstatus = get_scanid(folders, scans)

    # Check if scan is completed
    if scanstatus != "completed" and scanstatus != "imported":
        logging.error("Scan status: \"%s\"", scanstatus)
        sys.exit(1)

    history = []
    if args.diff:
        # Get history IDs
        details = scan_details(scanid)
        count = len(details["history"])
        if count <= 1:
            logging.error("There is only one scan history - diff not possible!")
            sys.exit()
        history.append(int(details["history"][count-1]["history_id"]))
        history.append(int(details["history"][count-2]["history_id"]))

        # Create diff
        scan_diff(scanid, history)

    # Trigger report generation
    token = export_request(scanid, history)

    # Wait for report to be genereated
    while (filestatus := tokens_status(token)) == "loading":
        time.sleep(5)

    # Download report
    if filestatus == "ready":
        filename = tokens_download(token)
    else:
        logging.error("An error occured!")
        sys.exit(1)


if __name__ == "__main__":
    main()
