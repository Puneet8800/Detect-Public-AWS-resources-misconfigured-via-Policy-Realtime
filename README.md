# Detect-Public-AWS-resources-misconfigured-via-Policy

# Purpose

The purpose of this automation is to detect Public AWS services which is misconfigured by AWS policies Realtime, After detecting this automation will send an alert on slack mentioning the policy json at the same time:
[Link]() 


# Deployment Options

* AWS Lambda

# Configuration Steps

* Create a Cloudwatch rule and paste the json of cloudwatch_rule.json in that rule.
* Trigger lambda via cloudwatch rule.
* In slack_alerts() please put the incoming webhook url of slack channel.

# Services this tool covers

* SQS
* SNS
* ECR
* KMS
* Secretmanager
* Glacier
* ES

# TODO
* I will be covering lot more services which can be made public via miscofigured AWS policies.
