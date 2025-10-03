import os
import sys
from datetime import datetime, timezone
import requests
import json
from sbp.client.drivers.network_drivers import TCPDriver
from sbp.client import Client

# --- Configuration ---
# Skylark connection details (using standard NTRIP port for SSL)
SKYLARK_HOST = "eu.l1l2.skylark.swiftnav.com"
SKYLARK_PORT = 2101 
# SBP message type for the certificate chain
MSG_CERT_CHAIN_TYPE = 3081
# Alert if the certificate expires in less than this many days
EXPIRATION_THRESHOLD_DAYS = 30

# --- Get credentials and keys from GitHub Secrets ---
SKYLARK_USERNAME = os.environ.get("SKYLARK_USERNAME")
SKYLARK_PASSWORD = os.environ.get("SKYLARK_PASSWORD")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")

def send_slack_alert(message):
    """Sends a formatted message to a Slack webhook."""
    if not SLACK_WEBHOOK_URL:
        print("Slack webhook URL not found. Skipping alert.")
        return
    try:
        payload = {"text": f":warning: Skylark Certificate Alert: {message}"}
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        print("Slack alert sent successfully.")
    except Exception as e:
        print(f"Error sending Slack alert: {e}")

def send_pagerduty_alert(summary):
    """Sends an alert to PagerDuty."""
    if not PAGERDUTY_ROUTING_KEY:
        print("PagerDuty routing key not found. Skipping alert.")
        return
    try:
        payload = {
            "routing_key": PAGERDUTY_ROUTING_KEY,
            "event_action": "trigger",
            "payload": {
                "summary": summary,
                "source": "skylark-ssl-monitor",
                "severity": "warning",
            },
        }
        response = requests.post(
            "https://events.pagerduty.com/v2/event", json=payload, timeout=10
        )
        response.raise_for_status()
        print("PagerDuty alert sent successfully.")
    except Exception as e:
        print(f"Error sending PagerDuty alert: {e}")

def check_certificate():
    """
    Connects to Skylark, finds the certificate chain message,
    and checks its expiration date.
    """
    # Use TCPDriver for the NTRIP connection
    driver = TCPDriver(
        SKYLARK_HOST,
        SKYLARK_PORT,
        ntrip_user=f"{SKYLARK_USERNAME}:{SKYLARK_PASSWORD}",
        # Mountpoint is not strictly needed for the cert, but good practice
        ntrip_mount="/SSR-integrity", 
    )

    print(f"Connecting to Skylark at {SKYLARK_HOST}:{SKYLARK_PORT}...")

    # The 'with' statement ensures the connection is properly closed
    with Client(driver) as client:
        try:
            # Iterate through incoming SBP messages
            for msg, _ in client.messages:
                if msg.msg_type == MSG_CERT_CHAIN_TYPE:
                    print("Found Certificate Chain message (SBP 3081).")
                    
                    # Extract the expiration date components from the message
                    exp = msg.expiration
                    expiration_date = datetime(
                        exp.year, exp.month, exp.day, exp.hour, exp.minute, exp.second, tzinfo=timezone.utc
                    )
                    
                    current_date = datetime.now(timezone.utc)
                    time_left = expiration_date - current_date
                    
                    print(f"Certificate expires on: {expiration_date.isoformat()}")
                    print(f"Current date is:       {current_date.isoformat()}")
                    print(f"Time until expiration: {time_left.days} days")

                    # Check if the expiration is within the threshold
                    if time_left.days < EXPIRATION_THRESHOLD_DAYS:
                        alert_message = (
                            f"Certificate expires in {time_left.days} days "
                            f"(on {expiration_date.strftime('%Y-%m-%d')}). "
                            f"Threshold is {EXPIRATION_THRESHOLD_DAYS} days."
                        )
                        print(f"\nALERT: {alert_message}")
                        send_slack_alert(alert_message)
                        send_pagerduty_alert(alert_message)
                        # Exit with an error code to make the GitHub Action fail
                        sys.exit(1) 
                    else:
                        print("\nOK: Certificate expiration is within acceptable range.")
                    
                    # We found the message, so we can stop.
                    return

        except KeyboardInterrupt:
            print("Process interrupted by user.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            sys.exit(1)

    print("Error: Did not receive a Certificate Chain message from Skylark.")
    sys.exit(1)

if __name__ == "__main__":
    check_certificate()
