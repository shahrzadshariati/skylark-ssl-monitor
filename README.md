# Skylark SSL Certificate Monitor

This project contains a Python script and GitHub Actions workflow to automatically monitor the expiration date of the SSL certificate for a Swift Navigation Skylark endpoint.

## How it Works

The GitHub Actions workflow runs on a daily schedule. It executes the `ssl_check_skylark.py` script, which:
1.  Connects to the Skylark NTRIP stream for 20 seconds.
2.  Parses the SBP certificate message to find the expiration date.
3.  Compares the expiration date to the current date.
4.  Sends alerts to Slack and PagerDuty if the certificate is expiring within a set threshold.

## Configuration

This workflow requires the following secrets to be configured in the GitHub repository's **Settings > Secrets and variables > Actions**:

-   `SKYLARK_USERNAME`: The username for the Skylark endpoint.
-   `SKYLARK_PASSWORD`: The password for the Skylark endpoint.
-   `SLACK_WEBHOOK_URL`: The incoming webhook URL for posting alerts to a Slack channel.
-   `PAGERDUTY_ROUTING_KEY`: The integration key (Events API V2) for triggering PagerDuty incidents.
