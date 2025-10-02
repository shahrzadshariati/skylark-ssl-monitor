# .github/workflows/ssl_check.yml

name: Daily Skylark SSL Certificate Check

# This workflow will run every day at 8:00 AM UTC.
# The 'cron' syntax is used for scheduling.
on:
  schedule:
    - cron: '0 8 * * *'
  # Allows you to run this workflow manually from the Actions tab
  workflow_dispatch:

jobs:
  check-certificate:
    runs-on: ubuntu-latest

    steps:
    # Step 1: Check out your repository code so the workflow can access the script
    - name: Check out repository
      uses: actions/checkout@v4

    # Step 2: Set up a Python environment
    - name: Set up Python 3.11
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    # Step 3: Install Python dependencies from requirements.txt
    - name: Install Python dependencies
      run: |
        python -m pip install --upgrade pip
        pip install requests

    # Step 4: Install the swift-nav command-line tools
    - name: Install swift-nav suite
      run: curl -sL https://raw.githubusercontent.com/swift-nav/suite/main/install.sh | bash

    # Step 5: Run the Python script
    # It uses GitHub Secrets for credentials and webhook URLs, passed as environment variables.
    - name: Run SSL Check Script
      env:
        SKYLARK_USERNAME: ${{ secrets.SKYLARK_USERNAME }}
        SKYLARK_PASSWORD: ${{ secrets.SKYLARK_PASSWORD }}
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
        PAGERDUTY_ROUTING_KEY: ${{ secrets.PAGERDUTY_ROUTING_KEY }}
      run: python3 ssl_check_skylark.py

