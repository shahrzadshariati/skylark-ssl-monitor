import os
import json
import subprocess
import time
from datetime import datetime, timedelta, timezone

# --- Configuration ---
SKYLARK_URL = "https://eu.l1l2.skylark.swiftnav.com:2102/SSR-integrity"
SKYLARK_LAT = 52.149
SKYLARK_LON = 13.096
NTRIP_TIMEOUT_SECONDS = 90
LOG_FILE = "log.rtcm.json"
ALERT_THRESHOLD_DAYS = 30
PAGER_THRESHOLD_DAYS = 7
SBP_MSG_TYPE = 3081

# --- Helper Functions ---

def get_credentials():
    """Retrieves credentials securely from environment variables."""
    username = os.environ.get("SKYLARK_USERNAME")
    password = os.environ.get("SKYLARK_PASSWORD")
    if not username or not password:
        print("Error: SKYLARK_USERNAME or SKYLARK_PASSWORD environment variables not set.")
        exit(1)
    return username, password

def send_slack_alert(channel: str, message: str):
    """Sends a formatted message to a specified Slack channel using a webhook URL."""
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
    """Sends an alert to PagerDuty using an Events API v2 integration key."""
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
    """Runs the ntripping command using its full path to avoid PATH issues."""
    # --- THIS IS THE DEFINITIVE FIX ---
    # Construct the full, absolute path to the executables.
    home_dir = os.path.expanduser('~')
    ntripping_path = os.path.join(home_dir, '.local', 'bin', 'ntripping')
    rtcm32json_path = os.path.join(home_dir, '.local', 'bin', 'rtcm32json')

    command = (
        f"{ntripping_path} --username {username} --password {password} "
        f"--url {SKYLARK_URL} --lat {SKYLARK_LAT} --lon {SKYLARK_LON} | "
        f"{rtcm32json_path} > {LOG_FILE}"
    )
    print(f"Starting NTRIP connection for {NTRIP_TIMEOUT_SECONDS} seconds...")
    process = None
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(NTRIP_TIMEOUT_SECONDS)
        process.terminate()
        
        stdout, stderr = process.communicate(timeout=5)
        if stderr:
            print("--- Start of NTRIP Command Error Log ---")
            print(stderr)
            print("--- End of NTRIP Command Error Log ---")

        print("NTRIP connection terminated.")
        return True
    except subprocess.TimeoutExpired:
        print("NTRIP process did not terminate in time, killing.")
        if process:
            process.kill()
        return True
    except Exception as e:
        print(f"An error occurred while running the ntripping command: {e}")
        return False


def find_and_parse_certificate():
    """Reads the log file and finds the first SBP certificate message."""
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        print(f"Error: Log file '{LOG_FILE}' was not created or is empty.")
        return None

    with open(LOG_FILE, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get("sbp", {}).get("msg_type") == SBP_MSG_TYPE:
                    print("Found SBP certificate message.")
                    return data["sbp"]["expiration"]
            except json.JSONDecodeError:
                continue
    return None

def main():
    """Main function to execute the SSL check procedure."""
    username, password = get_credentials()

    if not run_ntrip_command(username, password):
        exit(1)

    try:
        expiration_data = find_and_parse_certificate()

        if not expiration_data:
            error_message = (
                f"🚨 SCRIPT ERROR: Could not find certificate message in the output file ({LOG_FILE}) "
                f"after {NTRIP_TIMEOUT_SECONDS} seconds."
            )
            send_slack_alert("noc-alerts-test", error_message)
            exit(1)

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

        if days_until_expiry <= 0:
            message = f"🔥🔥🔥 CRITICAL ALERT: Skylark SSL certificate has EXPIRED!"
            send_slack_alert(channel="noc-alerts-test", message=message)
            send_pager_duty_alert(message=message, severity="critical")
        elif days_until_expiry <= PAGER_THRESHOLD_DAYS:
            message = f"🔥 PAGER ALERT: Certificate expiration to expire in {days_until_expiry} days."
            send_slack_alert(channel="noc-alerts-test", message=message)
            send_pager_duty_alert(message=message, severity="critical")
        elif days_until_expiry <= ALERT_THRESHOLD_DAYS:
            message = f"⚠️ WARNING: Certificate expiration to expire in {days_until_expiry} days."
            send_slack_alert(channel="noc-alerts-test", message=message)
        else:
            print("Certificate is valid and not expiring soon. No alert needed.")

    finally:
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
            print(f"Cleaned up {LOG_FILE}.")

if __name__ == "__main__":
    main()

