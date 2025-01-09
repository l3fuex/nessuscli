# Nessus Command Line Interface (nessuscli)

In the standard Nessus Professional WebUI it is possible to schedule scans and send reports automatically after a scan is finished. Unfortunately it is currently not possible to change the default report type in this scenario. This will always fallback to "Vulnerabilities by Host", which will get pretty noisy if you have a large target scope with lots of findings.  

Due to that limitation I wrote this piece of software with the main focus on being able to schedule reports but also with the thought in mind to do it in a way that I can easily add other functionalities in the future as needed. To achieve that, the software is splitted in two parts: The main part is the program `nessuscli.py`, which implements the api communication and interaction with nessus itself. Additionally, a wrapper program `wrapper.py`, which is based on the main logic of nessuscli, implements the functionality of sending given scan reports via email. Scan reports of the same scan are only sent once so that the program can be executed regularly, e.g. as a cronjob, without spamming someone's mailbox.

The program can be executed on any host in the network - it is not necessary to run it directly on the nessus host. Obviously access to the Nessus API is mandatory for the software to work.

## Dependencies
- Python >= 3.10

## Installation
```bash
# Copy the code to your machine
git clone https://github.com/l3fuex/nessuscli

# Add Nessus API keys and SNMTP server settings to the configuration file
mv nessuscli/config.ini.example nessuscli/config.ini && chmod 600 nessuscli/config.ini
vi nessuscli/config.ini

# Make the script executable
chmod +x nessuscli/*.py
````

## Usage

As of now nessuscli comes with two main modes: **scan** and **report**. **scan** gives you access to some basic information of a given scan like the status while **report** is the entry point for anything related to report generation.
```bash
python3 nessuscli.py scan "Test Scan" --status
python3 nessuscli.py scan "Test Scan" --last-scanned
python3 nessuscli.py scan "Test Scan" --targets
python3 nessuscli.py scan "Test Scan" --vulnstats

python3 nessuscli.py report "Test Scan"
python3 nessuscli.py report "Test Scan" --format pdf
python3 nessuscli.py report "Test Scan" --format pdf --severity high,critical --type vuln_by_plugin
```

### Report scheduling
You can schedule report generation by adding a crontab entry which executes the wrapper like every 5 minutes. The example outlined below sends reports, only including findings with a severity of "high" or "critical", in the format "pdf" and "csv".
```bash
# Add a crontab entry to schedule the wrapper execution
conrtab -l
*/5 * * * * /usr/bin/python3 ~/nessuscli/wrapper.py "Test Scan" --format pdf,csv --severity high,critical --type vuln_by_plugin> /dev/null 2>&1
```
