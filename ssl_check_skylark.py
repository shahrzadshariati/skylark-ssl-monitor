import os
import sys
import time
import base64
from datetime import datetime, timezone
import requests
# The Framer is the correct class for parsing SBP message streams.
from sbp.client.framer import Framer
from sbp.client.drivers.network_drivers import TCPDriver

# --- Configuration ---
SKYLARK_HOST = "eu.l1l2.skylark.swiftnav.com"
SKYLARK_PORT = 2101
SKYLARK_MOUNTPOINT = "/SSR-integrity"
MSG_CERT_CHAIN_TYPE = 3081
EXPIRATION_THRESHOLD_DAYS = 30
# CHANGE 1: Increased recording duration from 60 to 120 seconds.
RECORDING_DURATION_SECONDS = 120
DATA_FILENAME = "skylark_data.sbp" # Temporary file to store data

# --- Get credentials and keys from GitHub Secrets ---
SKYLARK_USERNAME = os.environ.get("SKYLARK_USERNAME")
SKYLARK_PASSWORD = os.environ.get("SKYLARK_PASSWORD")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
PAGERDUTY_ROUTING_KEY = os.environ.get("PAGERDUTY_ROUTING_KEY")

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

def run_check():
    driver = None
    try:
        # --- STAGE 1: CONNECT AND RECORD DATA ---
        print(f"--- STAGE 1 of 3: Connecting to {SKYLARK_HOST}:{SKYLARK_PORT} ---")
        driver = TCPDriver(SKYLARK_HOST, SKYLARK_PORT, timeout=20)
        
        creds = f"{SKYLARK_USERNAME}:{SKYLARK_PASSWORD}".encode("ascii")
        auth_header = b"Authorization: Basic " + base64.b64encode(creds)
        request = (
            f"GET {SKYLARK_MOUNTPOINT} HTTP/1.1\r\nHost: {SKYLARK_HOST}\r\n"
            "Ntrip-Version: Ntrip/2.0\r\nUser-Agent: SBP-Python-Client/1.0\r\n"
        ).encode("ascii") + auth_header + b"\r\n\r\n"
        driver.write(request)
        
        response = driver.read(1024)
        
        if b"200 OK" not in response:
            print(f"❌ FATAL ERROR: NTRIP handshake failed. Server response: {response.decode('ascii', errors='ignore')}")
            sys.exit(1)
        print("✅ STAGE 1 SUCCESS: Connection and NTRIP login successful.")

        # --- STAGE 2: RECORD DATA TO A FILE ---
        print(f"--- STAGE 2 of 3: Recording data for {RECORDING_DURATION_SECONDS} seconds to '{DATA_FILENAME}' ---")
        start_time = time.time()
        bytes_written = 0
        with open(DATA_FILENAME, "wb") as f:
            while time.time() - start_time < RECORDING_DURATION_SECONDS:
                data = driver.read(4096)
                if not data:
                    break
                f.write(data)
                bytes_written += len(data)
        print(f"✅ STAGE 2 SUCCESS: Finished recording. Wrote {bytes_written} bytes.")

    except Exception as e:
        print(f"❌ FATAL ERROR during connection or recording: {e}")
        sys.exit(1)
    finally:
        if driver:
            driver.close()
            print("INFO: Network connection closed.")

    # --- STAGE 3: PARSE THE FILE AND CHECK THE CERTIFICATE ---
    print(f"--- STAGE 3 of 3: Analyzing '{DATA_FILENAME}' for certificate message ---")
    cert_found = False
    try:
        with open(DATA_FILENAME, "rb") as f:
            framer = Framer(f.read, write=None)
            for msg in framer:
                # CHANGE 2: Added this debug line to print every message type found.
                print(f"DEBUG: Found message with type: {msg.msg_type}")
                if msg.msg_type == MSG_CERT_CHAIN_TYPE:
                    cert_found = True
                    print("✅ Found Certificate Chain message (SBP 3081).")
                    
                    exp = msg.expiration
                    expiration_date = datetime(exp.year, exp.month, exp.day, exp.hour, exp.minute, exp.second, tzinfo=timezone.utc)
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
                        print("✅ STAGE 3 SUCCESS: Certificate expiration is within acceptable range.")
                    break # Exit loop once certificate is found
            
        if not cert_found:
            print(f"❌ FATAL ERROR: Ran successfully but did not find a certificate message (SBP 3081) in the recorded data.")
            sys.exit(1)

    except Exception as e:
        print(f"❌ FATAL ERROR during file parsing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_check()
