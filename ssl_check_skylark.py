import subprocess
import json
import os
from datetime import datetime, timezone, timedelta

# --- Configuration ---
USERNAME = os.environ.get("SKYLARK_USERNAME", "swiftnoc@cx1")
PASSWORD = os.environ.get("SKYLARK_PASSWORD", "noctesting")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")

NTRIP_URL = "https://eu.l1l2.skylark.swiftnav.com:2102/SSR-integrity"
LAT = "52.149"
LON = "13.096"

LOG_FILE = "log.rtcm.json"
NTRIP_TIMEOUT_SECONDS = 20
ALERT_THRESHOLD_DAYS = 30
PAGER_THRESHOLD_DAYS = 7

# --- Helper Functions ---

def send_slack_alert(channel: str, message: str):
    """Placeholder to send a message to a Slack channel."""
    print(f"--- SIMULATING SLACK ALERT to #{channel} ---")
    print(message)
    print("------------------------------------------")

    if not SLACK_WEBHOOK_URL or SLACK_WEBHOOK_URL == 'waiting-for-approval':
        print("WARNING: SLACK_WEBHOOK_URL is not set. Cannot send real alert.")
        return

    import requests
    payload = {"channel": f"#{channel}", "text": message}
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        response.raise_for_status()
        print("Successfully sent Slack alert.")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to send Slack alert: {e}")

def send_pager_duty_alert(message: str, severity: str = "critical"):
    """Placeholder to trigger a PagerDuty incident."""
    print(f"--- SIMULATING PAGERDUTY ALERT ({severity}) ---")
    print(message)
    print("------------------------------------------")

    if not PAGERDUTY_ROUTING_KEY or PAGERDUTY_ROUTING_KEY == 'waiting-for-approval':
        print("WARNING: PAGERDUTY_ROUTING_KEY is not set. Cannot send real alert.")
        return
        
    import requests
    url = "https://events.pagerduty.com/v2/enqueue"
    payload = {
        "routing_key": PAGERDUTY_ROUTING_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": message,
            "source": "skylark-ssl-monitor",
            "severity": severity,
        }
    }
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        print("Successfully sent PagerDuty alert.")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to send PagerDuty alert: {e}")

# --- Main Script Logic ---

def main():
    """Main function to run the SSL certificate check."""
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    command = (
        f"swift ntripping --username {USERNAME} --password {PASSWORD} "
        f"--url {NTRIP_URL} --lat {LAT} --lon {LON} | "
        f"swift rtcm32json > {LOG_FILE}"
    )

    print(f"Starting NTRIP connection for {NTRIP_TIMEOUT_SECONDS} seconds...")
    process = None
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait(timeout=NTRIP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        print("NTRIP connection timeout reached, terminating process.")
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("Process did not terminate gracefully, killing.")
            process.kill()
    except Exception as e:
        print(f"An error occurred while running the ntripping command: {e}")
        return

    print("NTRIP connection closed.")

    if not os.path.exists(LOG_FILE):
        print(f"ERROR: {LOG_FILE} was not created. Cannot check certificate.")
        return

    expiration_date = None
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get("sbp", {}).get("msg_type") == 3081:
                        exp = data["sbp"]["expiration"]
                        expiration_date = datetime(
                            exp["year"], exp["month"], exp["day"],
                            exp["hours"], exp["minutes"], exp["seconds"],
                            tzinfo=timezone.utc
                        )
                        print(f"Found certificate. Expiration Date (UTC): {expiration_date}")
                        break
                except (json.JSONDecodeError, KeyError):
                    continue
    except Exception as e:
        print(f"An error occurred while reading or parsing {LOG_FILE}: {e}")
        return

    if expiration_date:
        current_date_utc = datetime.now(timezone.utc)
        days_until_expiry = (expiration_date - current_date_utc).days

        print(f"Current Date (UTC): {current_date_utc}")
        print(f"Days until certificate expires: {days_until_expiry}")

        if days_until_expiry < 0:
            message = f"🚨 CRITICAL: Skylark SSL certificate has EXPIRED!"
            send_slack_alert(channel="noc-alerts-test", message=message)
            send_pager_duty_alert(message=message, severity="critical")
        
        elif days_until_expiry <= PAGER_THRESHOLD_DAYS:
            message = f"🔥 PAGER ALERT: Skylark SSL certificate expires in {days_until_expiry} days on {expiration_date.date()}."
            send_slack_alert(channel="noc-alerts-test", message=message)
            send_pager_duty_alert(message=message, severity="critical")

        elif days_until_expiry <= ALERT_THRESHOLD_DAYS:
            message = f"⚠️ WARNING: Skylark SSL certificate expires in {days_until_expiry} days on {expiration_date.date()}."
            send_slack_alert(channel="noc-alerts-test", message=message)
        else:
            print("✅ Certificate is valid and not expiring soon. No action needed.")
    else:
        message = "🚨 MONITORING FAILURE: Could not find SSL certificate message (SBP 3081) in the Skylark NTRIP stream."
        send_slack_alert(channel="noc-alerts-test", message=message)
        send_pager_duty_alert(message=message, severity="warning")

    finally:
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
            print(f"Cleaned up {LOG_FILE}.")

if __name__ == "__main__":
    main()

