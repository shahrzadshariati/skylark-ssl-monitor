import sys
import os

# --- NEW DEBUGGING CODE ADDED ---
# This will print the exact paths where this script is looking for libraries.
# This is the final piece of the puzzle.
print("--- Python Sys Path ---")
print(sys.path)
print("-----------------------")

try:
    from sbp.client.drivers.network_client import NetworkClient
    from sbp.table import dispatch
    from sbp.system import MsgStartup
    from sbp.piksi import MsgThreadState
    from sbp.integrity import MsgSsrCertificate
except ImportError:
    print("Error: The 'sbp' library is not installed. Please run 'pip install sbp'.")
    sys.exit(1)

import datetime
import json
import requests
import time

# --- Constants ---
# Increased timeout to ensure we capture the certificate message.
TIMEOUT_SECONDS = 90
ALERT_THRESHOLD_DAYS = 30
PAGER_THRESHOLD_DAYS = 7
LOG_FILE = "log.rtcm.json"

def send_slack_alert(channel: str, message: str):
    """Sends a message to a Slack channel using a webhook URL from secrets."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url or webhook_url == "waiting-for-approval":
        print(f"SKIPPING SLACK: Webhook URL not configured.")
        print(f"Would have sent to #{channel}: {message}")
        return
    try:
        payload = {"channel": f"#{channel}", "text": message}
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        print(f"Successfully sent Slack alert to #{channel}.")
    except requests.exceptions.RequestException as e:
        print(f"Error sending Slack alert: {e}")

def send_pager_duty_alert(message: str, severity: str):
    """Sends an alert to PagerDuty using a routing key from secrets."""
    routing_key = os.environ.get("PAGERDUTY_ROUTING_KEY")
    if not routing_key or routing_key == "waiting-for-approval":
        print(f"SKIPPING PAGERDUTY: Routing key not configured.")
        print(f"Would have sent PagerDuty alert: {message}")
        return
    try:
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": message,
                "severity": severity,
                "source": "GitHub Actions - Skylark Monitor",
            },
        }
        response = requests.post("https://events.pagerduty.com/v2/event", json=payload)
        response.raise_for_status()
        print("Successfully sent PagerDuty alert.")
    except requests.exceptions.RequestException as e:
        print(f"Error sending PagerDuty alert: {e}")

def main():
    """Main function to run the SSL check."""
    username = os.environ.get("SKYLARK_USERNAME")
    password = os.environ.get("SKYLARK_PASSWORD")
    url = "eu.l1l2.skylark.swiftnav.com:2102"
    
    certificate_message = None

    print(f"Starting NTRIP connection for {TIMEOUT_SECONDS} seconds...")
    try:
        with NetworkClient(url, username=username, password=password) as client:
            start_time = time.time()
            
            # The client.recv() call will block until a message is received.
            # We wrap it in a loop with a timeout.
            for msg, _ in client:
                if isinstance(msg, MsgSsrCertificate):
                    print("Found SBP certificate message!")
                    certificate_message = msg
                    break # Exit the loop once we have the message
                
                if time.time() - start_time > TIMEOUT_SECONDS:
                    print("Timeout reached.")
                    break
    except Exception as e:
        # This will catch connection errors, auth failures, etc.
        error_message = f"SCRIPT ERROR: An exception occurred during NTRIP connection: {e}"
        print(error_message)
        send_slack_alert(channel="noc-alerts-test", message=error_message)
        sys.exit(1)


    if not certificate_message:
        error_message = f"SCRIPT ERROR: Could not find certificate message in the output file ({LOG_FILE}) after {TIMEOUT_SECONDS} seconds."
        print(error_message)
        send_slack_alert(channel="noc-alerts-test", message=error_message)
        sys.exit(1)

    try:
        # Extract expiration date from the certificate message
        exp = certificate_message.expiration
        exp_date = datetime.datetime(
            exp.year, exp.month, exp.day, exp.hour, exp.minute, exp.second,
            tzinfo=datetime.timezone.utc
        )
        current_date = datetime.datetime.now(datetime.timezone.utc)
        days_until_expiry = (exp_date - current_date).days

        print(f"Certificate expires on: {exp_date.isoformat()}")
        print(f"Current date is: {current_date.isoformat()}")
        print(f"Days until expiry: {days_until_expiry}")

        if days_until_expiry <= 0:
            message = f"🔥 PAGER ALERT: CRITICAL! Certificate has EXPIRED!"
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

    except Exception as e:
        error_message = f"SCRIPT ERROR: Could not parse certificate data. Error: {e}"
        print(error_message)
        send_slack_alert(channel="noc-alerts-test", message=error_message)
        sys.exit(1)

if __name__ == "__main__":
    main()

