# Microsoft Sentinel / Defender triage query examples

These KQL snippets are **illustrative, unexecuted examples** for the synthetic cases in [`data/triage-cases.json`](../data/triage-cases.json). They are not findings, detection rules, or proof of tenant integration. Confirm your workspace, product licenses, ingestion, permissions, retention, and table schema before adapting them. Never query or export employer/third-party data without authorization. A matching row is an investigation lead, not proof of malicious activity.

## Sentinel / Log Analytics: sign-in review

```kusto
// Exercise only; not executed against a tenant.
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName =~ "analyst1@example.invalid"
   or IPAddress == "203.0.113.42"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          Location, IsInteractive, ResultType, ResultDescription
| take 100
```

`SigninLogs` is populated from Microsoft Entra sign-in data when the connector and applicable licensing are configured. Interactive and non-interactive sign-ins may be represented in different tables. Validate the account, device, application, MFA result, expected VPN/travel, and related activity with trusted sources; an IP or location alone is not proof.

## Defender advanced hunting: endpoint process review

```kusto
// Exercise only; not executed against a tenant.
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName =~ "LAB-WS-01"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, ProcessUniqueId,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| take 100
```

`DeviceProcessEvents` depends on Defender for Endpoint telemetry. Correlate process identity, parent-child context, device and time; process IDs can be reused, so use `ProcessUniqueId` where available. Never execute an unknown payload as part of this lab.

## Defender advanced hunting: email scope review

```kusto
// Exercise only; not executed against a tenant.
EmailEvents
| where Timestamp > ago(7d)
| where NetworkMessageId == "SYNTH-MSG-003"
| project Timestamp, NetworkMessageId, SenderFromAddress,
          RecipientEmailAddress, Subject, ThreatTypes,
          DeliveryAction, DeliveryLocation
| take 100
```

`EmailEvents` depends on Defender for Office 365 telemetry. A message can produce multiple records as threat verdict or delivery location changes; determine final state using current guidance and an appropriate latest-event strategy before reporting recipient exposure.

## References

- [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Connect Microsoft Entra ID data to Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory)
- [Advanced hunting schema tables](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [DeviceProcessEvents table reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [EmailEvents table reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)
- [Advanced hunting query best practices](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices)
