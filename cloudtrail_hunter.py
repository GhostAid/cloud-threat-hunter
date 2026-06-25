import json

HIGH_RISK_EVENTS = [
    "CreateUser",
    "AttachUserPolicy",
    "CreateAccessKey",
    "DeleteTrail",
    "StopLogging"
]

MEDIUM_RISK_EVENTS = [
    "ListUsers",
    "ListRoles",
    "ListBuckets"
]

high_count = 0
medium_count = 0
low_count = 0

with open("sample_logs/sample-cloudtrail.json", "r") as file:
    data = json.load(file)

print("\n=== CloudTrail Threat Hunter ===\n")

for event in data["Records"]:
    event_name = event.get("eventName")

    if event_name in HIGH_RISK_EVENTS:
        print(f"[HIGH] {event_name}")
        high_count += 1

    elif event_name in MEDIUM_RISK_EVENTS:
        print(f"[MEDIUM] {event_name}")
        medium_count += 1

    else:
        print(f"[LOW] {event_name}")
        low_count += 1


print("\n=== Detection Summary ===")
print(f"High Severity Events: {high_count}")
print(f"Medium Severity Events: {medium_count}")
print(f"Low Severity Events: {low_count}")


report = f"""
# CloudTrail Detection Report

## Summary

High Severity Events: {high_count}
Medium Severity Events: {medium_count}
Low Severity Events: {low_count}

## Findings

Potential suspicious activity detected in CloudTrail logs.

## Analyst Notes

Review IAM activity and failed access attempts.
"""

with open("reports/detection-report.md", "w") as file:
    file.write(report)

print("\nReport saved to reports/detection-report.md")
