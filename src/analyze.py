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
    """
    Returns:
      - failed_count: (user, ip) -> number of FAIL events
      - ip_to_users: ip -> set of unique users that failed from that IP
    """
    failed_count = defaultdict(int)
    ip_to_users = defaultdict(set)

    with open(input_file, "r") as file:
        for line in file:
            log = parse_log_line(line)

            if log.get("status") == "FAIL":
                user = log.get("user", "unknown")
                ip = log.get("ip", "unknown")

                failed_count[(user, ip)] += 1
                ip_to_users[ip].add(user)

    return failed_count, ip_to_users


def write_user_ip_report(failed_count, output_file: str, threshold: int):
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["User", "IP", "Failed Attempts", "Suspicious"])

        for (user, ip), count in failed_count.items():
            suspicious = "YES" if count >= threshold else "NO"
            writer.writerow([user, ip, count, suspicious])


def write_ip_suspicious_report(ip_to_users, output_file: str, user_threshold: int):
    """
    Flags an IP as suspicious if it has failed logins for >= user_threshold unique users.
    """
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Unique Users Targeted", "Users", "Suspicious"])

        for ip, users in ip_to_users.items():
            unique_user_count = len(users)
            suspicious = "YES" if unique_user_count >= user_threshold else "NO"
            writer.writerow([ip, unique_user_count, ";".join(sorted(users)), suspicious])


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs and detect suspicious failed logins."
    )
    parser.add_argument("--input", default="data/auth.log", help="Path to input log file")
    parser.add_argument("--output", default="output/report.csv", help="Path to user+IP output CSV report")
    parser.add_argument(
        "--threshold", type=int, default=3,
        help="Failed attempts threshold per (user, ip) to mark suspicious"
    )

    # New output + threshold for IP attacking multiple users
    parser.add_argument(
        "--ip-output", default="output/ip_suspicious.csv",
        help="Path to IP-based suspicious activity report"
    )
    parser.add_argument(
        "--ip-user-threshold", type=int, default=2,
        help="Unique users per IP to mark it suspicious"
    )

    args = parser.parse_args()

    failed_count, ip_to_users = analyze_logs(args.input)
    write_user_ip_report(failed_count, args.output, args.threshold)
    write_ip_suspicious_report(ip_to_users, args.ip_output, args.ip_user_threshold)

    print(f"User+IP report generated at {args.output}")
    print(f"IP suspicious report generated at {args.ip_output}")


if __name__ == "__main__":
    main()
