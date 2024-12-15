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


def export_request(scanid, fileformat):
    url = f"{BASEURL}/scans/{scanid}/export"
    headers = {
        "X-ApiKeys": f"accessKey={ACCESSKEY}; secretKey={SECRETKEY}",
    }
    data = {
        "format":fileformat,
        "chapters":"vuln_by_plugin",
        "filter.0.quality":"eq",
        "filter.0.filter":"severity",
        "filter.0.value":"3",
        "filter.1.quality":"eq",
        "filter.1.filter":"severity",
        "filter.1.value":"4",
        "filter.search_type":"or",
    }
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
    if scanstatus != "completed":
        logging.error("Scan is not completed!")
        sys.exit(1)

    # Trigger report generation
    token = export_request(scanid, args.format)

    # Wait for report to be genereated
    while (filestatus := tokens_status(token)) == "loading":
        time.sleep(5)

    # Download report
    if filestatus == "ready":
        filename = tokens_download(token)
    else:
        logging.error("Report generation aborted!")
        sys.exit(1)


if __name__ == "__main__":
    main()
