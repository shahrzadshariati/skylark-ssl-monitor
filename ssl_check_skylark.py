import json
import sys
from datetime import datetime, timezone
import requests
import os

# --- Configuration ---
JSON_FILENAME = "log.json"
MSG_CERT_CHAIN_TYPE = 3081
EXPIRATION_THRESHOLD_DAYS = 30

# --- Get credentials for alerting ---
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")

# --- Alerting Functions (copied from old script) ---
def send_slack_alert(message):
    if not SLACK_WEBHOOK_URL:
        print("INFO: Slack webhook URL not found. Skipping alert.")
        return
    try:
        payload = {"text": f":warning: Skylark Certificate Alert: {message}"}
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        print("INFO: Slack alert sent successfully.")
    except Exception as e:
        print(f"ERROR: Failed to send Slack alert: {e}")

def send_pagerduty_alert(summary):
    if not PAGERDUTY_ROUTING_KEY:
        print("INFO: PagerDuty routing key not found. Skipping alert.")
        return
    try:
        payload = {
            "routing_key": PAGERDUTY_ROUTING_KEY, "event_action": "trigger",
            "payload": {"summary": summary, "source": "skylark-ssl-monitor", "severity": "warning"},
        }
        response = requests.post("https://events.pagerduty.com/v2/event", json=payload, timeout=10)
        response.raise_for_status()
        print("INFO: PagerDuty alert sent successfully.")
    except Exception as e:
        print(f"ERROR: Failed to send Pagerduty alert: {e}")

# --- Main Logic ---
def check_log_file():
    cert_found = False
    try:
        with open(JSON_FILENAME, 'r') as f:
            for line in f:
                try:
                    msg = json.loads(line)
                    # Check if the message contains the sbp data and has the correct type
                    if 'sbp' in msg and msg['sbp'].get('msg_type') == MSG_CERT_CHAIN_TYPE:
                        cert_found = True
                        print("✅ Found Certificate Chain message (SBP 3081).")
                        
                        exp = msg['sbp']['expiration']
                        expiration_date = datetime(exp['year'], exp['month'], exp['day'], exp['hour'], exp['minutes'], exp['seconds'], tzinfo=timezone.utc)
                        current_date = datetime.now(timezone.utc)
                        time_left = expiration_date - current_date

                        print(f"INFO: Certificate expires on: {expiration_date.isoformat()}")
                        print(f"INFO: Current date is:       {current_date.isoformat()}")
                        print(f"INFO: Time until expiration: {time_left.days} days")

                        if time_left.days < EXPIRATION_THRESHOLD_DAYS:
                            alert_message = (
                                f"Certificate expires in {time_left.days} days "
                                f"(on {expiration_date.strftime('%Y-%m-%d')}). "
                                f"Threshold is {EXPIRATION_THRESHOLD_DAYS} days."
                            )
                            print(f"🚨 ALERT: {alert_message}")
                            send_slack_alert(alert_message)
                            send_pagerduty_alert(alert_message)
                            sys.exit(1)
                        else:
                            print("✅ SUCCESS: Certificate expiration is within acceptable range.")
                        
                        # Exit successfully once the certificate is found and checked
                        return

                except json.JSONDecodeError:
                    # Ignore lines that are not valid JSON
                    continue

        if not cert_found:
            alert_message = f"Certificate message (SBP {MSG_CERT_CHAIN_TYPE}) was NOT found in the log file."
            print(f"❌ FATAL ERROR: {alert_message}")
            send_slack_alert(alert_message)
            send_pagerduty_alert(alert_message)
            sys.exit(1)

    except FileNotFoundError:
        print(f"❌ FATAL ERROR: Log file '{JSON_FILENAME}' not found. The swift tools may have failed.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ FATAL ERROR during file parsing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    check_log_file()
