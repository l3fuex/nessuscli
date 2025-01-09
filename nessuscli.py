import argparse
import logging
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

        # Parse filename from HTTP header
        for header, value in headers:
            if header.lower() == "content-disposition":
                header_filename = value.split("filename=")[-1].strip("\"'")
                header_filename = Path(header_filename)

        # Build filename
        if filename is None:
            filename = header_filename.name
        else:
            filename = filename + header_filename.suffix

        # Build filepath
        if filepath is None:
            filepath = Path(__file__).resolve().parent
        else:
            filepath = Path(filepath)

        # Check if path is valid
        if not filepath.is_dir():
            logging.error("Folder \"%s\" does not exist!", filepath)
            raise SystemExit(1)

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
        raise SystemExit(1)

    scanid = status = None
    for s in scans:
        if s["name"] == scanname and s["folder_id"] == folderid:
            scanid = s["id"]
            status = s["status"]

    if scanid is None or status is None:
        logging.error("Scan \"%s\" does not exist!", scanname)
        raise SystemExit(1)

    return scanid, status


def report(args, config):
    api = NessusAPI(
        config.get("API", "url"),
        config.get("API", "accessKey"),
        config.get("API", "secretKey")
    )

    # Get scan ID for given name
    folders, scans = api.scan_list()
    scanid, status = get_scanid(args.scandir, args.name, folders, scans)

    if status != "completed":
        logging.error("Scan is not completed yet!")
        raise SystemExit(1)

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
        abspath = api.token_download(token, filepath=args.filepath, filename=args.filename)
        logging.info("Download finished!")
        print(abspath)
    else:
        logging.error("An error occured!")
        raise SystemExit(1)


def scan(args, config):
    api = NessusAPI(
        config.get("API", "url"),
        config.get("API", "accessKey"),
        config.get("API", "secretKey")
    )

    # Get scan ID for given name
    folders, scans = api.scan_list()
    scanid, status = get_scanid(args.scandir, args.name, folders, scans)

    if args.status:
        print(f"{status}")

    if args.last_scanned:
        details = api.scan_details(scanid)

        if "scan_end_timestamp" in details["info"]:
            ts = int(details["info"]["scan_end_timestamp"])
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))
            print(f"{ts}")

    if args.targets:
        details = api.scan_details(scanid)

        if "targets" in details["info"]:
            print(f"{details["info"]["targets"]}")

    if args.vulnstats:
        details = api.scan_details(scanid)

        if "vulnerabilities" in details:
            info = low = medium = high = critical = 0
            for vuln in details["vulnerabilities"]:
                if vuln["severity"] == 0:
                    info += int(vuln["count"])
                if vuln["severity"] == 1:
                    low += int(vuln["count"])
                if vuln["severity"] == 2:
                    medium += int(vuln["count"])
                if vuln["severity"] == 3:
                    high += int(vuln["count"])
                if vuln["severity"] == 4:
                    critical += int(vuln["count"])

        print(f"critical: {critical}")
        print(f"high:     {high}")
        print(f"medium:   {medium}")
        print(f"low:      {low}")
        print(f"info:     {info}")


def main():
    def create_type_handler(allowed_values):
        def type_handler(value):
            values = value.split(",")
            # Check for valid values
            for value in values:
                if value not in allowed_values:
                    raise argparse.ArgumentTypeError(
                        f"invalid choice: \'{value}\' (choose from {", ".join(f'\'{item}\'' for item in allowed_values)})"
                    )
            return set(values)
        return type_handler


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
        help="Scan name"
    )
    report_parser.add_argument(
        "--scandir",
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
        default="vuln_by_plugin"
    )
    report_parser.add_argument(
        "--severity",
        help="Specify relevant severity level(s)",
        type=create_type_handler(["info", "low", "medium", "high", "critical"]),
        default=["info", "low", "medium", "high", "critical"]
    )
    report_parser.add_argument(
        "--filename",
        help="Filename to be used for report",
        default=None
    )
    report_parser.add_argument(
        "--filepath",
        help="Filepath to directory where report should be saved",
        default=None
    )
    report_parser.set_defaults(func=report)

    # Define arguments for "scan" option
    scan_parser = subparsers.add_parser("scan", help="Get information about scans")
    scan_parser.add_argument(
        "name",
        type=str,
        help="Scan name"
    )
    scan_parser.add_argument(
        "--scandir",
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
    group.add_argument(
        "--targets",
        help="List of target IPs / Networks",
        action="store_true"
    )
    group.add_argument(
        "--vulnstats",
        help="Vulnerability statistics",
        action="store_true"
    )
    scan_parser.set_defaults(func=scan)

    # Function call
    args = parser.parse_args()
    args.func(args, config)


if __name__ == "__main__":
    main()
