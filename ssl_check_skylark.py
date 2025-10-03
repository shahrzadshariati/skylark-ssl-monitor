name: Daily Skylark SSL Certificate Check

on:
  schedule:
    - cron: '0 8 * * *'
  workflow_dispatch:

jobs:
  check-certificate:
    runs-on: ubuntu-latest

    steps:
    - name: Check out repository
      uses: actions/checkout@v4

    - name: Set up Python 3.11
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - name: Create Venv, Install, Verify, and Run Script
      env:
        SKYLARK_USERNAME: ${{ secrets.SKYLARK_USERNAME }}
        SKYLARK_PASSWORD: ${{ secrets.SKYLARK_PASSWORD }}
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
        PAGERDUTY_ROUTING_KEY: ${{ secrets.PAGERDUTY_ROUTING_KEY }}
      run: |
        # --- SETUP ---
        echo "Step 1: Creating and activating virtual environment..."
        python3 -m venv venv
        source venv/bin/activate

        # --- INSTALLATION ---
        echo "Step 2: Installing dependencies with setuptools..."
        python3 -m pip install --upgrade pip
        python3 -m pip install requests sbp setuptools

        # --- VERIFICATION ---
        echo "Step 3: Verifying installation with a deep import..."
        python3 -c "from sbp.client.drivers.network_driver import TCPDriver; print('--- DEEP VERIFICATION SUCCESS ---')"
        
        # --- EXECUTION ---
        echo "Step 4: Running the final script..."
        python3 ssl_check_skylark.py

