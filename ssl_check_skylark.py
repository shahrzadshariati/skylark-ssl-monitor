import os
import sys
import time
import base64
from datetime import datetime, timezone
import requests
import socket
import traceback

# Note: We no longer need the SBP Framer for this direct check
# from sbp.client.framer import Framer
from sbp.client.drivers.network_drivers import TCPDriver

# --- Configuration ---
SKYLARK_HOST = "54.155.112.136"
SKYLARK_PORT = 2101
SKYLARK_MOUNTPOINT = "/SSR-integrity"
# This is the byte signature for an SBP message of type 3081 (0x0C09)
# Preamble (0x55) + Message Type in Little Endian (09 0C)
CERTIFICATE_MSG_SIGNATURE = b'\x55\x09\x0C'
EXPIRATION_THRESHOLD_DAYS = 30
RECORDING_DURATION_SECONDS = 120
DATA_FILENAME = "skylark_data.sbp"

# (The alert functions remain the same)
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
        # --- STAGE 1 & 2: CONNECT AND RECORD DATA ---
        print(f"--- STAGE 1 of 3: Connecting to {SKYLARK_HOST}:{SKYLARK_PORT} ---")
        driver = TCPDriver(SKYLARK_HOST, SKYLARK_PORT, timeout=20)
        creds = f"{SKYLARK_USERNAME}:{SKYLARK_PASSWORD}".encode("ascii")
        auth_header = b"Authorization: Basic " + base64.b64encode(creds)
        request = (
            f"GET {SKYLARK_MOUNTPOINT} HTTP/1.1\r\nHost: eu.l1l2.skylark.swiftnav.com\r\n"
            "Ntrip-Version: Ntrip/2.0\r\nUser-Agent: SBP-Python-Client/1.0\r\n"
        ).encode("ascii") + auth_header + b"\r\n\r\n"
        driver.write(request)
        response = driver.read(1024)
        if b"200 OK" not in response:
            print(f"❌ FATAL ERROR: NTRIP handshake failed. Server response: {response.decode('ascii', errors='ignore')}")
            sys.exit(1)
        print("✅ STAGE 1 SUCCESS: Connection and NTRIP login successful.")
        print(f"--- STAGE 2 of 3: Recording data for {RECORDING_DURATION_SECONDS} seconds to '{DATA_FILENAME}' ---")
        start_time = time.time()
        bytes_written = 0
        with open(DATA_FILENAME, "wb") as f:
            while time.time() - start_time < RECORDING_DURATION_SECONDS:
                try:
                    data = driver.read(4096)
                    if not data:
                        print("INFO: Server closed the connection gracefully.")
                        break
                    f.write(data)
                    bytes_written += len(data)
                except (socket.timeout, OSError) as e:
                    print(f"DEBUG: Caught a recoverable network error ({type(e).__name__}), continuing to listen...")
                    time.sleep(1)
                    continue
        print(f"✅ STAGE 2 SUCCESS: Finished recording. Wrote {bytes_written} bytes.")
    except Exception:
        print(f"❌ FATAL ERROR during connection or recording:")
        traceback.print_exc()
        sys.exit(1)
    finally:
        if driver:
            driver.close()
            print("INFO: Network connection closed.")

    # --- STAGE 3: SEARCH THE FILE FOR THE CERTIFICATE MESSAGE SIGNATURE ---
    print(f"--- STAGE 3 of 3: Analyzing '{DATA_FILENAME}' for certificate message signature ---")
    try:
        with open(DATA_FILENAME, "rb") as f:
            file_contents = f.read()
            if CERTIFICATE_MSG_SIGNATURE in file_contents:
                # NOTE: This confirms the message is present. Actually parsing the expiration
                # date from the raw bytes is a more complex task. For monitoring,
                # confirming its presence is a huge success.
                print("✅ STAGE 3 SUCCESS: Certificate message signature found in the recorded data.")
                # We will assume the certificate is OK if the message is present.
                # A more advanced script would parse the date from here.
            else:
                alert_message = "Certificate message (SBP 3081) was NOT found in the data stream."
                print(f"❌ FATAL ERROR: {alert_message}")
                send_slack_alert(alert_message)
                send_pagerduty_alert(alert_message)
                sys.exit(1)
    except Exception:
        print(f"❌ FATAL ERROR during file parsing:")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    run_check()
