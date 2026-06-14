
import csv
import sqlite3
from collections import Counter
from datetime import datetime, timedelta

# File names
DATABASE_FILE = "security_logs.db"
CSV_FILE = "login_events.csv"
OUTPUT_FILE = "security_report.txt"

# Thresholds for determining if an IP is suspicious within 5 minutes
HIGH_THRESHOLD_RISK = 10
MEDIUM_THRESHOLD_RISK = 5
LOW_THRESHOLD_RISK = 3
TIME_WINDOW_MINUTES = 5

# Create the login_events database
def create_database(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL
        )
        """
    )
    connection.commit()


# Clear tables before running program
def clear_table(connection: sqlite3.Connection) -> None:
    connection.execute("DELETE FROM login_events")
    connection.execute("DELETE FROM sqlite_sequence WHERE name = 'login_events'")
    connection.commit()


# Import events from the included login_events.csv into a database
def import_events(connection: sqlite3.Connection) -> None:
    with open(CSV_FILE, "r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            connection.execute(
                """
                INSERT INTO login_events
                (timestamp, username, ip_address, status)
                VALUES (?, ?, ?, ?)
                """,
                (
                    row["timestamp"],
                    row["username"],
                    row["ip_address"],
                    row["status"],
                ),
            )

    connection.commit()


# Classify risk by count
def classify_risk(count):
    if count >= HIGH_THRESHOLD_RISK:
        return "HIGH"
    elif count >= MEDIUM_THRESHOLD_RISK:
        return "MEDIUM"
    elif count >= LOW_THRESHOLD_RISK:
        return "LOW"
    else:
        return "NORMAL"
    

# Provide textual recommendations based on risk level
def get_recommendation(risk):
    if risk == "HIGH":
        return "Block IP, enforce MFA, review logs, and alert security team."
    elif risk == "MEDIUM":
        return "Monitor IP, rate-limit login attempts, and require stronger authentication."
    elif risk == "LOW":
        return "Watch for repeated failures and review account lockout settings."
    else:
        return "No immediate action needed."
    

# Calculate max attempts in a specific window
# Thanks to ChatGPT for helping me create this function
def get_max_attempts_in_window(timestamps):
    time_window = timedelta(minutes=TIME_WINDOW_MINUTES)
    max_attempts = 0

    for start_index in range(len(timestamps)):
        window_start = timestamps[start_index]
        window_end = window_start + time_window
        count = 0

        for timestamp in timestamps:
            if window_start <= timestamp <= window_end:
                count += 1

        max_attempts = max(max_attempts, count)

    return max_attempts
    

# Analysis of failed login patterns from the data and create a report
def analyze_failed_logins(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT timestamp, ip_address FROM login_events
        WHERE status = 'failed'
        ORDER BY ip_address, timestamp
        """
    ).fetchall()

    failed_logins_ip = {}
    suspicious_find = False

    for timestamp_text, ip_address in rows:
            timestamp = datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")

            if ip_address not in failed_logins_ip:
                failed_logins_ip[ip_address] = []

            failed_logins_ip[ip_address].append(timestamp)

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as file:
        file.write("Security Login Analysis Report\n")
        file.write("-" * 40 + "\n")

        for ip_address, timestamps in failed_logins_ip.items():
            max_attempts_in_window = get_max_attempts_in_window(timestamps)
            risk = classify_risk(max_attempts_in_window)
            if risk == "NORMAL":
                continue
            suspicious_find = True
            recommendation = get_recommendation(risk)

            file.write(f"\nIP Address: {ip_address}\n")
            file.write(f"Max Failed Attempts in {TIME_WINDOW_MINUTES} Minutes: {max_attempts_in_window}\n")
            file.write(f"Risk Level: {risk}\n")
            file.write("CIA Impact: Confidentiality\n")
            file.write(f"Recommended Defense: {recommendation}\n")

        if not suspicious_find:
            file.write("No failed login attempts found.\n")


def main():
    try:
        with sqlite3.connect(DATABASE_FILE) as connection:
            create_database(connection)
            clear_table(connection)
            import_events(connection)
            analyze_failed_logins(connection)
    except FileNotFoundError:
        print(f"Error: {CSV_FILE} was not found.")
    except sqlite3.Error as error:
        print(f"Database error: {error}")
    except KeyError as error:
        print(f"CSV column missing: {error}")


# Ensure this script is not called outside running main
if __name__ == "__main__":
    main()
