import argparse
import logging
import sys
import json
from urllib import request, parse
import time
from pathlib import Path
import configparser

logging.basicConfig(
#    level=logging.DEBUG, format="%(levelname)-8s %(funcName)s:%(lineno)d - %(message)s"
    level=logging.INFO, format="%(levelname)-8s %(message)s"
)


class NessusAPI:
    def __init__(self, baseurl, accesskey, secretkey):
        self.baseurl = baseurl
        self.accesskey = accesskey
        self.secretkey = secretkey


    def scan_list(self):
        url = f"{self.baseurl}/scans"
        headers = { "X-ApiKeys": f"accessKey={self.accesskey}; secretKey={self.secretkey}" }

        data, _ = self._send_request(url, headers=headers)
        data = json.loads(data.decode())

        return data["folders"], data["scans"]


    def scan_details(self, scanid, limit=1):
        url = f"{self.baseurl}/scans/{scanid}?limit={limit}"
        headers = { "X-ApiKeys": f"accessKey={self.accesskey}; secretKey={self.secretkey}" }

        data, _ = self._send_request(url, headers=headers)
        data = json.loads(data.decode())

        return data


    def export_request(self, scanid, reportformat, reporttype, severity, history=None):
        url = f"{self.baseurl}/scans/{scanid}/export"
        if history:
            url += f"?diff_id={history[0]}&history_id={history[1]}&limit=2500"

        headers = { "X-ApiKeys": f"accessKey={self.accesskey}; secretKey={self.secretkey}" }

        params = { "format": reportformat }
        params = params | { "chapters": reporttype }
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

        data, _ = self._send_request(url, headers=headers, data=params, method="POST")
        data = json.loads(data.decode())

        return data["token"], data["file"]


    def token_status(self, token):
        url = f"{self.baseurl}/tokens/{token}/status"
        headers = {"X-ApiKeys": f"accessKey={self.accesskey}; secretKey={self.secretkey}"}

        data, _ = self._send_request(url, headers)
        data = json.loads(data.decode())

        return data["error"], data["message"], data["status"]


    def token_download(self, token, filepath=None, filename=None):
        url = f"{self.baseurl}/tokens/{token}/download"
        headers = {"X-ApiKeys": f"accessKey={self.accesskey}; secretKey={self.secretkey}"}

        data, headers = self._send_request(url, headers)

        # If filename does not exist, parse filename from HTTP header
        if filename is None:
            for header, value in headers:
                if header == "Content-Disposition":
                    filename = value.split("filename=")[-1]
                    filename = filename.strip("\"'")

        # If filepath does not exist, take the program directory as filepath
        if filepath is None:
            filepath = Path(__file__).resolve().parent

        abspath = filepath / filename
        with open(abspath, "wb") as file:
            file.write(data)

        return abspath


    def _send_request(self, url, headers=None, data=None, method="GET"):
        logging.debug("%s %s", method, url)

        # URL encode POST data
        if data:
            logging.debug("DATA: %s", data)
            data = parse.urlencode(data).encode("utf-8")

        # Send request
        req = request.Request(url, headers=headers, data=data, method=method)
        with request.urlopen(req) as response:
            response_data = response.read()
            response_headers = response.getheaders()

        return response_data, response_headers


def get_scanid(dirname, scanname, dirs, scans):
    folderid = None
    for d in dirs:
        if d["name"] == dirname:
            folderid = d["id"]

    if folderid is None:
        logging.error("Folder \"%s\" does not exist!", dirname)
        sys.exit(1)

    scanid = status = None
    for s in scans:
        if s["name"] == scanname and s["folder_id"] == folderid:
            scanid = s["id"]
            status = s["status"]

    if scanid is None or status is None:
        logging.error("Scan \"%s\" does not exist!", scanname)
        sys.exit(1)

    return scanid, status


def report(args, config):
    api = NessusAPI(
        config.get("Nessus", "url"),
        config.get("Nessus", "accessKey"),
        config.get("Nessus", "secretKey")
    )

    # Get scan ID for given name
    folders, scans = api.scan_list()
    scanid, status = get_scanid(args.dir, args.name, folders, scans)

    if status == "running":
        logging.error("Scan is still running!")
        sys.exit(1)

    # Trigger report generation
    token, _ = api.export_request(scanid, args.format, args.type, args.severity)

    # Wait for report to be genereated
    while True:
        _ , message, status = api.token_status(token)
        logging.info("[%s] %s", status, message)
        if status != "loading":
            break
        time.sleep(5)

    # Download report
    if status == "ready":
        abspath = api.token_download(token)
        logging.info("Download finished! >> \"%s\"", abspath)
    else:
        logging.error("An error occured!")
        sys.exit(1)


def scan(args, config):
    api = NessusAPI(
        config.get("Nessus", "url"),
        config.get("Nessus", "accessKey"),
        config.get("Nessus", "secretKey")
    )

    # Get scan ID for given name
    folders, scans = api.scan_list()
    scanid, status = get_scanid(args.dir, args.name, folders, scans)

    if args.status:
        print(f"{status}")

    if args.last_scanned:
        details = api.scan_details(scanid)

        ts = "N/A"
        if "scan_end_timestamp" in details["info"]:
            ts = int(details["info"]["scan_end_timestamp"])
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))

        print(f"{ts}")


def main():
    def severity_type_handler(value):
        valid_severities = ["info", "low", "medium", "high", "critical"]
        severities = value.split(",")
        # Input validation
        for severity in severities:
            if severity not in valid_severities:
                raise argparse.ArgumentTypeError(
                    f"invalid choice: \'{severity}\' (choose from {", ".join(f'\'{item}\'' for item in valid_severities)})"
                )
        # Remove duplicates
        severities = list(dict.fromkeys(severities))

        return severities


    # Read config.ini file
    config = configparser.ConfigParser()
    config.read(Path(__file__).resolve().parent / "config.ini")

    # Create argumet parser and subparsers
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(required=True)

    # Define arguments for "report" option
    report_parser = subparsers.add_parser("report", help="Generates reports from completed scans")
    report_parser.add_argument(
        "name",
        type=str,
        help="Scan name",
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
        help="Specify relevant severity level",
        type=severity_type_handler,
        default=["info", "low", "medium", "high", "critical"]
    )
    report_parser.set_defaults(func=report)

    # Define arguments for "scan" option
    scan_parser = subparsers.add_parser("scan", help="Get information about scans")
    scan_parser.add_argument(
        "name",
        type=str,
        help="Scan name",
    )
    scan_parser.add_argument(
        "--dir",
        help="Scan directory",
        default="My Scans"
    )
    group = scan_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--status",
        help="Shows the status of a scan",
        action="store_true"
    )
    group.add_argument(
        "--last-scanned",
        help="Timestamp of last scan (UTC)",
        action="store_true"
    )
    scan_parser.set_defaults(func=scan)

    # Function call
    args = parser.parse_args()
    args.func(args, config)


if __name__ == "__main__":
    main()
