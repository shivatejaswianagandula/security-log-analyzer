import csv
import argparse
from collections import defaultdict

def parse_log_line(line: str) -> dict:
    parts = line.strip().split()
    data = {}
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            data[key] = value
    return data


def analyze_logs(input_file: str):
    failed_count = defaultdict(int)

    with open(input_file, "r") as file:
        for line in file:
            log = parse_log_line(line)
            if log.get("status") == "FAIL":
                user = log.get("user", "unknown")
                ip = log.get("ip", "unknown")
                failed_count[(user, ip)] += 1

    return failed_count


def write_report(results, output_file: str, threshold: int):
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["User", "IP", "Failed Attempts", "Suspicious"])

        for (user, ip), count in results.items():
            suspicious = "YES" if count >= threshold else "NO"
            writer.writerow([user, ip, count, suspicious])


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs and detect suspicious failed logins."
    )
    parser.add_argument("--input", default="data/auth.log", help="Path to input log file")
    parser.add_argument("--output", default="output/report.csv", help="Path to output CSV report")
    parser.add_argument(
        "--threshold", type=int, default=3,
        help="Number of failed attempts to mark suspicious"
    )

    args = parser.parse_args()

    results = analyze_logs(args.input)
    write_report(results, args.output, args.threshold)
    print(f"Report generated at {args.output}")


if __name__ == "__main__":
    main()
