import csv
from pathlib import Path
import re
import sys

file_path = Path(sys.argv[-1]).resolve()

# Read nessus csv data
with open(file_path, mode="r", encoding="utf-8") as csv_file:
    old_data = csv.DictReader(csv_file, delimiter=",")
    headers = old_data.fieldnames
    old_data = sorted(old_data, key=lambda line: line["Plugin ID"])

# Reformat data structure
new_data = []
counter = 0
pline = {}
for line in old_data:
    if counter > 0 and pline["Plugin ID"] == line["Plugin ID"] and pline["Port"] == line["Port"]:
        for key, value in line.items():
            if value == pline[key]:
                pass
            elif re.findall(value, pline[key]):
                pass
            elif not re.findall(value, pline[key]):
                new_data[counter-1][key] += f", {value}"
            else:
                new_data[counter-1][key] = value

    else:
        new_data.append(line)
        counter += 1

    pline = line

# Write newly formated csv file
with open("output.csv", mode="w", encoding="utf-8") as csv_file:
    writer = csv.DictWriter(csv_file, fieldnames=new_data[0].keys())
    writer.writeheader()
    writer.writerows(new_data)