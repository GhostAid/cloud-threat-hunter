# CloudTrail Threat Hunter

## Overview

CloudTrail Threat Hunter is a Python-based security tool that analyzes AWS CloudTrail logs and identifies potentially suspicious activity. The tool categorizes events by severity level and automatically generates a detection report to assist with incident investigations.

## Features

* Detects high-risk AWS IAM activity
* Identifies reconnaissance-related actions
* Categorizes events as High, Medium, or Informational severity
* Generates automated Markdown reports
* Provides a detection summary for analysts

## Technologies Used

* Python 3
* AWS CloudTrail
* JSON
* Git
* GitHub

## Detection Logic

The tool parses CloudTrail log records and extracts the eventName field. Events are compared against predefined detection rules and assigned a severity level.

## High-Risk Events

* CreateUser
* AttachUserPolicy
* CreateAccessKey
* DeleteTrail
* StopLogging

## Medium-Risk Events

* ListUsers
* ListRoles
* ListBuckets

## Sample Output

=== CloudTrail Threat Hunter ===
[MEDIUM] ListUsers
[HIGH] CreateUser
[MEDIUM] ListBuckets
=== Detection Summary ===
High Severity Events: 1
Medium Severity Events: 2
Informational Severity Events: 0
Report saved to reports/detection-report.md

## Generated Report

The tool automatically generates a Markdown report containing:

* Detection summary
* Severity counts
* Investigation findings
* Analyst notes

  ## Analyst Assessments

The detection engine identified six CloudTrail events across different severity levels.

High Severity

Three high-severity events were detected. These include IAM-related actions that could indicate potentially unauthorized account or access changes. These events should be prioritized for investigation.

Medium Severity

Two medium-severity events were detected. These include reconnaissance-related actions that may indicate attempts to gather information about AWS users or resources.

Informational

One informational event was detected. This event provides additional context for understanding the sequence of activity but does not independently indicate a confirmed security incident.

Overall Assessment

The results demonstrate how CloudTrail Threat Hunter can identify and prioritize potentially suspicious AWS activity. Analysts can use the severity classifications to focus investigation efforts on the most significant events while correlating them with timestamps, identities, source IP addresses, and other CloudTrail activity.

## Future Improvements

* MITRE ATT&CK Mapping
* Real CloudTrail Log Ingestion
* CSV Report Export
* Email Alerting
* IP Reputation Checking
* CloudWatch Integration

## Skills Demonstrated

* Cloud Security
* Detection Engineering
* Threat Hunting
* Python Scripting
* Log Analysis
* AWS Security Monitoring
* Incident Response
