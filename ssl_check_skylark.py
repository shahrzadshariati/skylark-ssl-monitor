import os
import time
import base64
from datetime import datetime, timezone
import socket

try:
    from sbp.client.drivers.network_driver import TCPDriver
    from sbp.client import Framer
    from sbp.ssr import MsgSsrCertificate
except ImportError:
    print("Error: The 'sbp' library is not installed. Please run 'pip install sbp'.")
    exit(1)

# --- Configuration ---
SKYLARK_HOST = "eu.l1l2.skylark.swiftnav.com"
SKYLARK_PORT = 2102
SKYLARK_MOUNTPOINT = "/SSR-integrity"
CONNECTION_TIMEOUT_SECONDS = 90
ALERT_THRESHOLD_DAYS = 30
PAGER_THRESHOLD_DAYS = 7
SBP_MSG_TYPE = 0x0C09 # SBP message type for MsgSsrCertificate is 3081 (0x0C09)

# --- Helper Functions ---

def get_credentials():
    """Retrieves credentials securely from environment variables."""
    username = os.environ.get("SKYLARK_USERNAME")
    password = os.environ.get("SKYLARK_PASSWORD")
    if not username or not password:
        print("Error: SKYLARK_USERNAME or SKYLARK_PASSWORD environment variables not set.")
        exit(1)
    return username, password

def send_slack_alert(message: str):
    """Sends a formatted message to the test Slack channel."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url or webhook_url == "waiting-for-approval":
        print("Slack alert not sent: SLACK_WEBHOOK_URL is not configured.")
        print(f"Message: {message}")
        return
    try:
        import requests
        payload = {"channel": "#noc-alerts-test", "text": message}
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        print("Successfully sent Slack alert.")
    except Exception as e:
        print(f"Error sending Slack alert: {e}")

def send_pager_duty_alert(message: str, severity: str = "critical"):
    """Sends an alert to PagerDuty."""
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
            "payload": {"summary": message, "severity": severity, "source": "GitHub Actions - Skylark SSL Monitor"},
        }
        response = requests.post("https://events.pagerduty.com/v2/event", json=payload)
        response.raise_for_status()
        print("Successfully sent PagerDuty alert.")
    except Exception as e:
        print(f"Error sending PagerDuty alert: {e}")

def get_certificate_from_skylark(username, password):
    """Connects to Skylark natively and listens for the certificate message."""
    # Ntrip 1.0 login required for Skylark
    auth_string = f"{username}:{password}"
    auth_b64 = base64.b64encode(auth_string.encode('ascii')).decode('ascii')
    request = (
        f"GET {SKYLARK_MOUNTPOINT} HTTP/1.0\r\n"
        f"User-Agent: SBP-Client/1.0\r\n"
        f"Authorization: Basic {auth_b64}\r\n"
        f"\r\n"
    )

    print(f"Connecting to {SKYLARK_HOST}:{SKYLARK_PORT}...")
    try:
        with TCPDriver(SKYLARK_HOST, SKYLARK_PORT) as driver:
            driver.write(request.encode('ascii'))
            framer = Framer(driver.read)
            
            start_time = time.time()
            while time.time() - start_time < CONNECTION_TIMEOUT_SECONDS:
                try:
                    # Non-blocking read with a short timeout
                    msg, _ = framer.next(timeout=1.0)
                    if msg is not None and msg.msg_type == SBP_MSG_TYPE:
                        print("Found SBP certificate message.")
                        return msg
                except (socket.timeout, StopIteration):
                    # No message received, continue waiting
                    continue
            print("Connection timed out waiting for certificate message.")
            return None
    except Exception as e:
        print(f"An error occurred during the Skylark connection: {e}")
        return None

def main():
    """Main function to execute the SSL check procedure."""
    username, password = get_credentials()
    certificate_msg = get_certificate_from_skylark(username, password)

    if not certificate_msg:
        error_message = (
            f"🚨 SCRIPT ERROR: Could not find SBP certificate message from Skylark "
            f"after {CONNECTION_TIMEOUT_SECONDS} seconds."
        )
        send_slack_alert(error_message)
        exit(1)

    # Extract expiration data from the SBP message
    exp = certificate_msg.expiration
    exp_date = datetime(exp.year, exp.month, exp.day, exp.hours, exp.minutes, tzinfo=timezone.utc)
    current_date = datetime.now(timezone.utc)
    days_until_expiry = (exp_date - current_date).days

    print(f"Certificate expires on: {exp_date.strftime('%Y-%m-%d')}")
    print(f"Days until expiration: {days_until_expiry}")

    if days_until_expiry <= 0:
        message = f"🔥🔥🔥 CRITICAL ALERT: Skylark SSL certificate has EXPIRED!"
        send_slack_alert(message)
        send_pager_duty_alert(message)
    elif days_until_expiry <= PAGER_THRESHOLD_DAYS:
        message = f"🔥 PAGER ALERT: Certificate expiration to expire in {days_until_expiry} days."
        send_slack_alert(message)
        send_pager_duty_alert(message)
    elif days_until_expiry <= ALERT_THRESHOLD_DAYS:
        message = f"⚠️ WARNING: Certificate expiration to expire in {days_until_expiry} days."
        send_slack_alert(message)
    else:
        print("Certificate is valid and not expiring soon. No alert needed.")

if __name__ == "__main__":
    main()

