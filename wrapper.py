import argparse
import subprocess
import re
import time
import calendar
from pathlib import Path
import hashlib
import smtplib
from email.message import EmailMessage
import mimetypes
import logging
import configparser

logging.basicConfig(
    level=logging.DEBUG, format="%(levelname)-8s %(funcName)s:%(lineno)d - %(message)s"
#    level=logging.INFO, format="%(levelname)-8s %(message)s"
)


def send_mail(attachments):
    mimetypes.add_type("application/xml", ".nessus")

    config = configparser.ConfigParser()
    config.read(Path(__file__).resolve().parent / "config.ini")

    server = config.get("SMTP", "server")
    port = config.get("SMTP", "port")
    from_addr = config.get("SMTP", "from_addr")
    rcpt_addr = config.get("SMTP", "rcpt_addr")

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = rcpt_addr
    msg["Subject"] = "Nessus Report"
    msg.set_content("Nessus Report")

    for attachment in attachments:
        file_path = Path(attachment).resolve()
        mimetype, _ = mimetypes.guess_type(file_path)
        maintype, subtype = mimetype.split("/")
        logging.debug("Attaching file \"%s\" with mimetype \"%s\" and subtype \"%s\"", file_path.name, mimetype, subtype)
        with open(file_path, "rb") as file:
            file_data = file.read()
            msg.add_attachment(file_data, maintype=maintype, subtype=subtype, filename=file_path.name)

    try:
        with smtplib.SMTP(server, port) as server:
            server.starttls()
            server.send_message(msg)
            logging.info("Mail sent!")
    except smtplib.SMTPAuthenticationError as e:
        logging.error("Authentication error: %s", e)
    except smtplib.SMTPConnectError as e:
        logging.error("Connection error: %s", e)
    except smtplib.SMTPRecipientsRefused as e:
        logging.error("All recipients were refused: %s", e)
    except smtplib.SMTPException as e:
        logging.error("SMTP error: %s", e)
    except Exception as e:
        logging.error("Unexpected error: %s", e)


def wrapper(args):
    nessuscli = Path(__file__).resolve().parent / "nessuscli.py"

    # Get timestamp of last scan
    cmd = ["python3", str(nessuscli.resolve()), "scan", args.name, "--last-scanned"]
    logging.debug("Executing <%s>", " ".join(cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logging.debug("Output: %s", result.stdout.strip())
    except subprocess.CalledProcessError as e:
        logging.error("Command failed: %s", e.stderr.strip())
    except Exception as e:
        logging.error("Unexpected error while executing command: %s", e)

    # Check stdout for correct date format (e.g. 2024-01-01 06:00:00)
    pattern = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$"
    match = re.match(pattern, result.stdout)
    if not match:
        logging.debug("No date detected in output: \"%s\"", result.stdout)
        raise SystemExit

    # Convert date string to unix timestamp format
    date_struct = time.strptime(match.group(0), "%Y-%m-%d %H:%M:%S")
    ts1 = calendar.timegm(date_struct)

    # Build filename for state file
    md5hash = hashlib.md5((args.dir + args.name).encode()).hexdigest()
    filename = Path(__file__).resolve().parent / f".tmp_{md5hash}"

    # If current timestamp and state file timestamp match, do nothing
    if filename.exists():
        with open(filename, "r", encoding="utf-8") as file:
            ts2 = int(file.read())

        if ts1 == ts2:
            logging.info("No new scan data since last run - quitting")
            raise SystemExit

    # If state file does not exist or timestamps did not match, generate report
    attachments = []
    for file_format in args.format:
        cmd = ["python3", str(nessuscli.resolve()), "report", args.name, "--format", file_format, "--severity", ",".join(args.severity)]
        logging.debug("Executing <%s>", " ".join(cmd))

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logging.debug("Output: %s", result.stdout.strip())
            attachments.append(result.stdout.strip())
        except subprocess.CalledProcessError as e:
            logging.error("Command failed: %s", e.stderr.strip())
        except Exception as e:
            logging.error("Unexpected error while executing command: %s", e)

    # Send mail
    send_mail(attachments)

    # Write timestamp in state file
    with open(filename, "w", encoding="utf-8") as file:
        file.write(str(ts1))


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

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "name",
        type=str,
        help="Scan name"
    )
    parser.add_argument(
        "--dir",
        help="Scan directory",
        default="My Scans"
    )
    parser.add_argument(
        "--format",
        help="Report format(s)",
        type=create_type_handler(["pdf", "csv", "nessus"]),
        default=["pdf"]
    )
    parser.add_argument(
        "--type",
        choices=["vuln_hosts_summary", "vuln_by_host", "compliance_exec", "remediations", "vuln_by_plugin", "compliance"],
        help="Report type",
        default=["vuln_by_plugin"]
    )
    parser.add_argument(
        "--severity",
        help="Specify relevant severity level(s)",
        type=create_type_handler(["info", "low", "medium", "high", "critical"]),
        default=["info", "low", "medium", "high", "critical"]
    )
    args = parser.parse_args()

    wrapper(args)


if __name__ == "__main__":
    main()
