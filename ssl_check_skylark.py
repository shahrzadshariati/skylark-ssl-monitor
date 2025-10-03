import os
import sys
import json
from datetime import datetime, timezone

# --- Configuration ---
# Import SBP library, fail gracefully if not installed.
try:
    from sbp.client.drivers.network_driver import TCPDriver
    from sbp.client import Framer, Handler
    from sbp.msg import SBP_MSG_CERTIFICATE_CHAIN
except ImportError:
    print("Error: The 'sbp' library is not installed. Please run 'pip install sbp'.")
    sys.exit(1)

# Alerting thresholds (in days)
ALERT_THRESHOLD_DAYS = 30
PAGER_THRESHOLD_DAYS = 7

# Skylark endpoint details (read from environment variables for security)
SKYLARK_URL = "eu.l1l2.skylark.swiftnav.com"
SKYLARK_PORT = 2102
SKYLARK_USERNAME = os.environ.get("SKYLARK_USERNAME")
SKYLARK_PASSWORD = os.environ.get("SKYLARK_PASSWORD")
STREAM_NAME = "/SSR-integrity"

# Webhook URLs (read from environment variables)
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")

# --- Helper Functions ---
def send_slack_alert(channel: str, message: str):
    """Sends a message to a Slack channel using an incoming webhook."""
    if not SLACK_WEBHOOK_URL:
        print("WARNING: SLACK_WEBHOOK_URL is not set. Cannot send Slack alert.")
        return
    try:
        import requests
        payload = {"channel": f"#{channel}", "text": message}
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        response.raise_for_status()
        print(f"Successfully sent Slack alert to #{channel}.")
    except Exception as e:
        print(f"ERROR: Failed to send Slack alert: {e}")

def send_pager_duty_alert(message: str, severity: str = "critical"):
    """Sends an alert to PagerDuty using the Events API v2."""
    if not PAGERDUTY_ROUTING_KEY:
        print("WARNING: PAGERDUTY_ROUTING_KEY is not set. Cannot send PagerDuty alert.")
        return
    try:
        import requests
        payload = {
            "routing_key": PAGERDUTY_ROUTING_KEY,
            "event_action": "trigger",
            "payload": {
                "summary": message,
                "source": "skylark-ssl-monitor",
                "severity": severity,
            },
        }
        response = requests.post("https://events.pagerduty.com/v2/event", json=payload)
        response.raise_for_status()
        print("Successfully sent PagerDuty alert.")
    except Exception as e:
        print(f"ERROR: Failed to send PagerDuty alert: {e}")

def get_certificate_message(timeout: int = 90):
    """Connects to Skylark and waits for the certificate message."""
    full_url = f"{SKYLARK_USERNAME}:{SKYLARK_PASSWORD}@{SKYLARK_URL}:{SKYLARK_PORT}{STREAM_NAME}"
    cert_message = None

    print(f"Starting NTRIP connection for {timeout} seconds...")
    try:
        with TCPDriver(full_url) as driver:
            with Framer(driver.read, driver.write) as framer:
                # Use a list to store the message from the inner scope
                message_holder = []
                
                def callback(msg, **metadata):
                    if msg.msg_type == SBP_MSG_CERTIFICATE_CHAIN:
                        message_holder.append(msg)
                        # Stop the handler once we have the message
                        raise StopIteration

                handler = Handler(framer)
                handler.add_callback(callback)
                
                # Start the handler in a thread and wait for timeout or StopIteration
                handler.start()
                handler.join(timeout=timeout)

                if message_holder:
                    cert_message = message_holder[0]
                    
    except StopIteration:
        print("Successfully received certificate message.")
    except Exception as e:
        print(f"ERROR during NTRIP connection: {e}")
        return None
    finally:
        print("NTRIP connection terminated.")

    return cert_message


def main():
    """Main function to run the SSL check."""
    # 1. Get the certificate message from Skylark
    cert_msg = get_certificate_message()

    # 2. Check if we received the message
    if not cert_msg:
        error_message = "SCRIPT ERROR: Could not find certificate message in the data stream after 90 seconds."
        print(error_message)
        send_slack_alert(channel="noc-alerts-test", message=error_message)
        sys.exit(1)

    # 3. Extract and parse the expiration date
    try:
        exp = cert_msg.expiration
        exp_date = datetime(
            year=exp.year,
            month=exp.month,
            day=exp.day,
            hour=exp.hours,
            minute=exp.minutes,
            second=exp.seconds,
            tzinfo=timezone.utc,
        )
        current_date = datetime.now(timezone.utc)
        days_until_expiry = (exp_date - current_date).days
    except Exception as e:
        error_message = f"SCRIPT ERROR: Could not parse expiration date from certificate message. Error: {e}"
        print(error_message)
        send_slack_alert(channel="noc-alerts-test", message=error_message)
        sys.exit(1)
        
    print(f"Certificate expiration date (UTC): {exp_date.isoformat()}")
    print(f"Days until expiry: {days_until_expiry}")

    # 4. Compare dates and send alerts if necessary
    if days_until_expiry <= 0:
        message = f"🔥 PAGER ALERT: Certificate has EXPIRED! Expired {abs(days_until_expiry)} days ago."
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

if __name__ == "__main__":
    main()




