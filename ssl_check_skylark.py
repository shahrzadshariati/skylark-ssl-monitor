import os
import json
import subprocess
import time
from datetime import datetime, timedelta, timezone

# --- Configuration ---
SKYLARK_URL = "https://eu.l1l2.skylark.swiftnav.com:2102/SSR-integrity"
SKYLARK_LAT = 52.149
SKYLARK_LON = 13.096
# --- THIS IS THE LINE WE ARE CHANGING ---
NTRIP_TIMEOUT_SECONDS = 90  # Increased from 20 to 90 seconds
LOG_FILE = "log.rtcm.json"
ALERT_THRESHOLD_DAYS = 30
PAGER_THRESHOLD_DAYS = 7
SBP_MSG_TYPE = 3081

# --- Helper Functions ---

def get_credentials():
    """
    Retrieves credentials securely from environment variables.
    In GitHub Actions, these are set via repository secrets.
    """
    username = os.environ.get("SKYLARK_USERNAME")
    password = os.environ.get("SKYLARK_PASSWORD")
    if not username or not password:
        print("Error: SKYLARK_USERNAME or SKYLARK_PASSWORD environment variables not set.")
        print("Please configure them as secrets in your GitHub repository.")
        exit(1)
    return username, password

def send_slack_alert(channel: str, message: str):
    """
    Sends a formatted message to a specified Slack channel using a webhook URL.
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url or webhook_url == "waiting-for-approval":
        print("Slack alert not sent: SLACK_WEBHOOK_URL is not configured.")
        print(f"Message: {message}")
        return

    try:
        import requests
        payload = {"channel": f"#{channel}", "text": message}
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        print(f"Successfully sent Slack alert to #{channel}.")
    except Exception as e:
        print(f"Error sending Slack alert: {e}")

def send_pager_duty_alert(message: str, severity: str = "critical"):
    """
    Sends an alert to PagerDuty using an Events API v2 integration key.
    """
    routing_key = os.environ.get("PAGERDUTY_ROUTING_KEY")
    if not routing_key or routing_key == "waiting-for-approval":
        print("PagerDuty alert not sent: PAGERDUTY_ROUTING_KEY is not configured.")
        print(f"Message: {message}")
        return

    try:
        import requests
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": message,
                "severity": severity,
                "source": "GitHub Actions - Skylark SSL Monitor",
            },
        }
        response = requests.post("https://events.pagerduty.com/v2/event", json=payload)
        response.raise_for_status()
        print("Successfully sent PagerDuty alert.")
    except Exception as e:
        print(f"Error sending PagerDuty alert: {e}")


def run_ntrip_command(username, password):
    """
    Runs the swift ntripping command as a subprocess and logs output to a file.
    """
    command = (
        f"swift ntripping --username {username} --password {password} "
        f"--url {SKYLARK_URL} --lat {SKYLARK_LAT} --lon {SKYLARK_LON} | "
        f"swift rtcm32json > {LOG_FILE}"
    )
    print(f"Starting NTRIP connection for {NTRIP_TIMEOUT_SECONDS} seconds...")
    try:
        # We use shell=True because the command includes a pipe (|)
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(NTRIP_TIMEOUT_SECONDS)
        process.terminate()
        # Wait a moment for the process to terminate cleanly
        process.wait(timeout=5)
        print("NTRIP connection terminated.")
        return True
    except subprocess.TimeoutExpired:
        print("NTRIP process did not terminate in time, killing.")
        process.kill()
        return True # Still consider it a success as we likely got the data
    except Exception as e:
        print(f"An error occurred while running the ntripping command: {e}")
        # Capture and print stderr for debugging
        stderr = process.stderr.read().decode()
        if stderr:
            print(f"Error details: {stderr}")
        return False


def find_and_parse_certificate():
    """
    Reads the log file and finds the first SBP certificate message.
    """
    if not os.path.exists(LOG_FILE):
        print(f"Error: Log file '{LOG_FILE}' was not created.")
        return None

    with open(LOG_FILE, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("sbp", {}).get("msg_type") == SBP_MSG_TYPE:
                    print("Found SBP certificate message.")
                    return data["sbp"]["expiration"]
            except json.JSONDecodeError:
                continue # Ignore malformed lines
    return None

def main():
    """
    Main function to execute the SSL check procedure.
    """
    username, password = get_credentials()

    # Step 1: Run the NTRIP command to generate the log file
    if not run_ntrip_command(username, password):
        # The function already prints errors, just exit
        exit(1)

    try:
        # Step 2: Find and parse the certificate from the log file
        expiration_data = find_and_parse_certificate()

        if not expiration_data:
            print(f"Error: Could not find SBP message type {SBP_MSG_TYPE} in {LOG_FILE}.")
            send_slack_alert("noc-alerts-test", "🚨 SCRIPT ERROR: Could not find certificate message in Skylark log.")
            exit(1)

        # Step 3: Compare expiration date with the current date
        exp_date = datetime(
            expiration_data['year'],
            expiration_data['month'],
            expiration_data['day'],
            expiration_data['hours'],
            expiration_data['minutes'],
            tzinfo=timezone.utc
        )
        current_date = datetime.now(timezone.utc)
        days_until_expiry = (exp_date - current_date).days

        print(f"Certificate expires on: {exp_date.strftime('%Y-%m-%d')}")
        print(f"Days until expiration: {days_until_expiry}")

        # Step 4: Send alerts based on thresholds
        if days_until_expiry <= 0:
            message = f"🔥🔥🔥 CRITICAL ALERT: Skylark SSL certificate has EXPIRED!"
            send_slack_alert(channel="noc-alerts-test", message=message)
            send_pager_duty_alert(message=message, severity="critical")
        elif days_until_expiry <= PAGER_THRESHOLD_DAYS:
            message = f"🔥 PAGER ALERT: Skylark SSL certificate expires in {days_until_expiry} days on {exp_date.strftime('%Y-%m-%d')}."
            send_slack_alert(channel="noc-alerts-test", message=message)
            send_pager_duty_alert(message=message, severity="critical")
        elif days_until_expiry <= ALERT_THRESHOLD_DAYS:
            message = f"⚠️ WARNING: Skylark SSL certificate expires in {days_until_expiry} days on {exp_date.strftime('%Y-%m-%d')}."
            send_slack_alert(channel="noc-alerts-test", message=message)
        else:
            print("Certificate is valid and not expiring soon. No alert needed.")

    finally:
        # Step 5: Clean up the log file
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
            print(f"Cleaned up {LOG_FILE}.")

if __name__ == "__main__":
    main()

