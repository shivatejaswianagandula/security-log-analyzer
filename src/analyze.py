import csv
from collections import defaultdict

INPUT_FILE = "data/auth.log"
OUTPUT_FILE = "output/report.csv"


def parse_log_line(line: str) -> dict:
    parts = line.strip().split()
    data = {}

    for part in parts:
        if "=" in part:
            key, value = part.split("=")
            data[key] = value

    return data


def analyze_logs():
    failed_count = defaultdict(int)

    with open(INPUT_FILE, "r") as file:
        for line in file:
            log = parse_log_line(line)

            if log.get("status") == "FAIL":
                key = f"{log.get('user')}_{log.get('ip')}"
                failed_count[key] += 1

    return failed_count


def write_report(results):
    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["User", "IP", "Failed Attempts", "Suspicious"])

        for key, count in results.items():
            user, ip = key.split("_")
            suspicious = "YES" if count >= 3 else "NO"
            writer.writerow([user, ip, count, suspicious])


if __name__ == "__main__":
    results = analyze_logs()
    write_report(results)
    print("Report generated at output/report.csv")
