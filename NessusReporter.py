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
BASEURL= config.get("Nessus", "url")
ACCESSKEY= config.get("Nessus", "accessKey")
SECRETKEY= config.get("Nessus", "secretKey")

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
args = parser.parse_args()


def list_scans():
    url = f"{BASEURL}/scans"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}"
    }

    # TODO: Ignore SSL Certificate errors (disable in production environment)
    import ssl
    ssl_context = ssl._create_unverified_context()

    req = request.Request(url, headers=headers)
    with request.urlopen(req, context=ssl_context) as response:
        data = json.loads(response.read().decode())

    return data["folders"], data["scans"]


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


def export_request(scanid):
    def build_params():
        data = { "format": args.format }
        data = data | { "chapters": args.type }
        for index, severity in enumerate(args.severity):
            match severity:
                case "info":
                    data = data | {
                        f"filter.{index}.quality":"eq",
                        f"filter.{index}.filter":"severity",
                        f"filter.{index}.value":"0"
                    }
                case "low":
                    data = data | {
                        f"filter.{index}.quality":"eq",
                        f"filter.{index}.filter":"severity",
                        f"filter.{index}.value":"1"
                    }
                case "medium":
                    data = data | {
                        f"filter.{index}.quality":"eq",
                        f"filter.{index}.filter":"severity",
                        f"filter.{index}.value":"2"
                    }
                case "high":
                    data = data | {
                        f"filter.{index}.quality":"eq",
                        f"filter.{index}.filter":"severity",
                        f"filter.{index}.value":"3"
                    }
                case "critical":
                    data = data | {
                        f"filter.{index}.quality":"eq",
                        f"filter.{index}.filter":"severity",
                        f"filter.{index}.value":"4"
                    }
        data = data | { "filter.search_type":"or" }

        return data

    url = f"{BASEURL}/scans/{scanid}/export"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
    }
    data = build_params()

    data_encoded = parse.urlencode(data).encode("utf-8")

    # TODO: Ignore SSL Certificate errors (disable in production environment)
    import ssl
    ssl_context = ssl._create_unverified_context()

    req = request.Request(url, data=data_encoded, headers=headers, method="POST")
    with request.urlopen(req, context=ssl_context) as response:
        data = json.loads(response.read().decode())

    return data["token"]


def tokens_status(token):
    url = f"{BASEURL}/tokens/{token}/status"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
    }

    # TODO: Ignore SSL Certificate errors (disable in production environment)
    import ssl
    ssl_context = ssl._create_unverified_context()

    req = request.Request(url, headers=headers)
    with request.urlopen(req, context=ssl_context) as response:
        data = json.loads(response.read().decode())

    logging.info("Status: \"%s\"", data["status"])

    return data["status"]


def tokens_download(token):
    url = f"{BASEURL}/tokens/{token}/download"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
    }

    # TODO: Ignore SSL Certificate errors (disable in production environment)
    import ssl
    ssl_context = ssl._create_unverified_context()

    req = request.Request(url, headers=headers)
    with request.urlopen(req, context=ssl_context) as response:

        filename = response.getheader("Content-Disposition")
        filename = filename.split("filename=")[-1].strip("\"'")
        filename = Path(__file__).resolve().parent / filename

        with open(filename, "wb") as report:
            report.write(response.read())

    logging.info("Downloading file: \"%s\"", filename)

    return filename


def main():
    # Get scan ID
    folders, scans = list_scans()
    scanid, scanstatus = get_scanid(folders, scans)

    # Check if scan is completed
    if scanstatus != "completed" and scanstatus != "imported":
        logging.error("Scan status: \"%s\"", scanstatus)
        sys.exit(1)

    # Trigger report generation
    token = export_request(scanid)

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
