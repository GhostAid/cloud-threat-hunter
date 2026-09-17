import json

# High-risk CloudTrail events
HIGH_RISK_EVENTS = {
    "CreateUser": {
        "reason": "Creation of a new IAM user",
        "mitre": "T1136 - Create Account"
    },
    "AttachUserPolicy": {
        "reason": "IAM policy attached to a user",
        "mitre": "T1098 - Account Manipulation"
    },
    "CreateAccessKey": {
        "reason": "Creation of a new IAM access key",
        "mitre": "T1098 - Account Manipulation"
    },
    "DeleteTrail": {
        "reason": "CloudTrail trail deleted",
        "mitre": "T1562.001 - Impair Defenses"
    },
    "StopLogging": {
        "reason": "CloudTrail logging stopped",
        "mitre": "T1562.001 - Impair Defenses"
    }
}

# Medium-risk CloudTrail events
MEDIUM_RISK_EVENTS = {
    "ListUsers": {
        "reason": "IAM users enumerated",
        "mitre": "T1087.004 - Account Discovery: Cloud Account"
    },
    "ListRoles": {
        "reason": "IAM roles enumerated",
        "mitre": "T1087.004 - Account Discovery: Cloud Account"
    },
    "ListBuckets": {
        "reason": "S3 buckets enumerated",
        "mitre": "T1526 - Cloud Service Dashboard"
    }
}

high_count = 0
medium_count = 0
low_count = 0
informational_count = 0

findings = []

# Load CloudTrail log
with open("sample_logs/sample-cloudtrail.json", "r") as file:
    data = json.load(file)

print("\n=== CloudTrail Threat Hunter v2 ===\n")

for event in data.get("Records", []):

    event_name = event.get("eventName", "Unknown")
    event_time = event.get("eventTime", "Unknown")
    source_ip = event.get("sourceIPAddress", "Unknown")

    # Extract identity information
    user_identity = event.get("userIdentity", {})
    username = user_identity.get(
        "userName",
        user_identity.get("principalId", "Unknown")
    )

    # HIGH severity detection
    if event_name in HIGH_RISK_EVENTS:

        severity = "HIGH"
        high_count += 1

        reason = HIGH_RISK_EVENTS[event_name]["reason"]
        mitre = HIGH_RISK_EVENTS[event_name]["mitre"]

        print(f"[HIGH] {event_name}")
        print(f"  User: {username}")
        print(f"  Source IP: {source_ip}")
        print(f"  Time: {event_time}")
        print(f"  Reason: {reason}")
        print(f"  MITRE ATT&CK: {mitre}\n")

        findings.append({
            "severity": severity,
            "event": event_name,
            "user": username,
            "source_ip": source_ip,
            "time": event_time,
            "reason": reason,
            "mitre": mitre
        })

    # MEDIUM severity detection
    elif event_name in MEDIUM_RISK_EVENTS:

        severity = "MEDIUM"
        medium_count += 1

        reason = MEDIUM_RISK_EVENTS[event_name]["reason"]
        mitre = MEDIUM_RISK_EVENTS[event_name]["mitre"]

        print(f"[MEDIUM] {event_name}")
        print(f"  User: {username}")
        print(f"  Source IP: {source_ip}")
        print(f"  Time: {event_time}")
        print(f"  Reason: {reason}")
        print(f"  MITRE ATT&CK: {mitre}\n")

        findings.append({
            "severity": severity,
            "event": event_name,
            "user": username,
            "source_ip": source_ip,
            "time": event_time,
            "reason": reason,
            "mitre": mitre
        })

    # Events that are not currently classified
    else:
        informational_count += 1

        print(f"[INFO] {event_name}")

# Detection summary
print("\n=== Detection Summary ===")
print(f"High Severity Events: {high_count}")
print(f"Medium Severity Events: {medium_count}")
print(f"Informational Events: {informational_count}")

# Generate Markdown report
report = "# CloudTrail Detection Report\n\n"

report += "## Detection Summary\n\n"
report += f"- High Severity Events: {high_count}\n"
report += f"- Medium Severity Events: {medium_count}\n"
report += f"- Informational Events: {informational_count}\n\n"

report += "## Findings\n\n"

if findings:

    for finding in findings:

        report += f"### [{finding['severity']}] {finding['event']}\n\n"
        report += f"- **User:** {finding['user']}\n"
        report += f"- **Source IP:** {finding['source_ip']}\n"
        report += f"- **Timestamp:** {finding['time']}\n"
        report += f"- **Reason:** {finding['reason']}\n"
        report += f"- **MITRE ATT&CK:** {finding['mitre']}\n\n"

else:
    report += "No suspicious events were detected.\n"

report += "## Analyst Notes\n\n"
report += (
    "Review high-severity IAM activity first. "
    "Investigate the associated user identity, source IP address, "
    "timestamp, and surrounding CloudTrail events to determine "
    "whether the activity is authorized.\n"
)

# Save report
with open("reports/detection-report.md", "w") as file:
    file.write(report)

print("\nReport saved to reports/detection-report.md")



