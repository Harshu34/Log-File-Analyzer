import re
from collections import Counter
import csv

# File paths
log_file_path = "sample.log"
output_csv_path = "log_analysis_results.csv"



def parse_log_file(file_path):
    """Parses the log file and extracts information."""
    ip_addresses = []
    endpoints = []
    failed_logins = Counter()

    # Regular expressions for parsing
    ip_regex = r"^\d{1,3}(?:\.\d{1,3}){3}"
    endpoint_regex = r'"(?:GET|POST) (\S+) HTTP'
    failed_login_regex = r'"Invalid credentials"'

    with open(file_path, "r") as file:
        for line in file:
            # Extract IP addresses
            ip_match = re.search(ip_regex, line)
            if ip_match:
                ip = ip_match.group(0)
                ip_addresses.append(ip)

            # Extract endpoints
            endpoint_match = re.search(endpoint_regex, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoints.append(endpoint)

            # Identify failed logins
            if re.search(failed_login_regex, line) and ip_match:
                failed_logins[ip] += 1

    return ip_addresses, endpoints, failed_logins


def analyze_requests_per_ip(ip_addresses):
    """Counts requests per IP address."""
    return Counter(ip_addresses)


def analyze_most_frequent_endpoint(endpoints):
    """Identifies the most frequently accessed endpoint."""
    endpoint_counts = Counter(endpoints)
    most_common = endpoint_counts.most_common(1)
    if most_common:
        return most_common[0]
    return None, 0


def detect_suspicious_activity(failed_logins):
    """Returns all IPs with their failed login attempt counts."""
    return dict(failed_logins)  



def save_to_csv(ip_requests, top_endpoint, suspicious_activities, output_path):
    """Saves the results to a CSV file."""
    with open(output_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        writer.writerow([])

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([top_endpoint[0], top_endpoint[1]])

        writer.writerow([])

        # Write Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])


def main():
    # Step 1: Parse the log file
    ip_addresses, endpoints, failed_logins = parse_log_file(log_file_path)

    # Step 2: Analyze requests per IP
    ip_requests = analyze_requests_per_ip(ip_addresses)

    # Step 3: Find the most frequently accessed endpoint
    top_endpoint = analyze_most_frequent_endpoint(endpoints)

    # Step 4: Detect suspicious activity
    suspicious_activities = detect_suspicious_activity(failed_logins)

    # Step 5: Output results
    print("\nRequests per IP Address:")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if top_endpoint:
        print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activities.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_to_csv(ip_requests, top_endpoint, suspicious_activities, output_csv_path)
    print(f"\nResults saved to {output_csv_path}")


if __name__ == "__main__":
    main()
