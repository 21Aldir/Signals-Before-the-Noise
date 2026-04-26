# Proactive Hunt Brief — Hunt 03: Signals Before the Noise

> **Classification:** External RDP Compromise  
> **Phases:** 7 (ATT&CK Kill Chain)

## Evidence
<img width="440" height="844" alt="image" src="https://github.com/user-attachments/assets/fec6e90e-00c6-42af-a9d8-2b991917bad7" />

<img width="1363" height="996" alt="image" src="https://github.com/user-attachments/assets/ccfbdf64-29a9-44da-96bd-82f8a343c061" />




---

## Background

PHTG rolled out **HealthCloud** on 11 December 2025 as an internal endpoint health service. Scheduled PowerShell tasks, background service executables, and diagnostic cache directories under `C:\ProgramData\PHTG\HealthCloud\` were all expected. All by design.

---

## Trigger

A colleague announces a new day on PHTG's HealthCloud rollout on LinkedIn. The photo shows a dev workstation, a cloud console, and enough infrastructure detail to make you uncomfortable. You have been asked to familiarise yourself with HealthCloud's footprint so future alerts have context.

---

## Your Directive

There is no incident. There are no alerts. There is no suspected compromise. Yet. Review the publicly visible evidence. Determine what was exposed. Investigate whether the exposure was exploited. Follow the telemetry wherever it leads.

---

## Hunt Lead // Opening Brief

> *"Someone on the cloud team posted a photo on LinkedIn. Workstation, Azure portal open, VM details on screen. Could be nothing. Could be everything."*
>
> *"I need you to figure out what was exposed, whether anyone noticed, and whether anyone acted on it. Start with the images. Extract what you can. Then pivot to telemetry. If someone used what was in that photo to get in, I want to know about it before they come back."*

---

## ⚠ OPSEC

This lab contains realistic MDE telemetry. IP addresses and hostnames represent simulated infrastructure.

**Do not submit IPs or domains to public threat intelligence platforms. Treat this like a real engagement. Investigate, do not interact.**

---

## Investigation Environment

<img width="949" height="498" alt="image" src="https://github.com/user-attachments/assets/34582a48-6390-4797-93b3-e5c948b541fd" />


**Schema Docs:**
- [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [DeviceLogonEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
- [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [DeviceEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)

---

## Reusable Snippets

### GeoIP Lookup

Several flags require geographic enrichment of IP addresses. Prepend this block to your query, then pipe your IP column through `evaluate ipv4_lookup(GeoTable, RemoteIP, network)`.

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                  continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
```

---

## Data Dictionary

### DeviceNetworkEvents — NETWORK

| Column | Description |
|---|---|
| TimeGenerated | Event timestamp (UTC) |
| DeviceName | Hostname of the reporting device |
| ActionType | ConnectionAttempt, InboundConnectionAccepted, ConnectionSuccess, etc. |
| RemoteIP | Remote IP address |
| RemoteIPType | Public or Private |
| LocalPort | Port on the local device |
| RemotePort | Port on the remote host |
| InitiatingProcessSHA256 | SHA256 of the process that initiated the connection |

### DeviceLogonEvents — AUTH

| Column | Description |
|---|---|
| TimeGenerated | Event timestamp (UTC) |
| DeviceName | Hostname of the reporting device |
| ActionType | LogonSuccess, LogonFailed |
| AccountName | Account used for authentication |
| LogonType | Network, RemoteInteractive, Interactive, etc. |
| RemoteIP | Source IP of the logon attempt |
| RemoteIPType | Public or Private |
| FailureReason | Reason for failed logons (e.g. InvalidUserNameOrPassword) |

### DeviceProcessEvents — PROCESS

| Column | Description |
|---|---|
| TimeGenerated | Event timestamp (UTC) |
| DeviceName | Hostname of the reporting device |
| FileName | Name of the executed process |
| ProcessCommandLine | Full command line of the process |
| InitiatingProcessFileName | Parent process name |
| InitiatingProcessCommandLine | Parent process command line |
| InitiatingProcessAccountName | Account that launched the process |
| SHA256 | SHA256 hash of the executable |

### DeviceFileEvents — FILE

| Column | Description |
|---|---|
| TimeGenerated | Event timestamp (UTC) |
| DeviceName | Hostname of the reporting device |
| ActionType | FileCreated, FileModified, FileRenamed, FileDeleted |
| FileName | Current file name |
| PreviousFileName | Previous file name (for renames) |
| FolderPath | Full path including file name |
| SHA256 | SHA256 hash of the file |
| InitiatingProcessAccountName | Account that performed the action |

### DeviceEvents — MISC

| Column | Description |
|---|---|
| TimeGenerated / Timestamp | Event timestamp (UTC) |
| DeviceName | Hostname of the reporting device |
| ActionType | AntivirusDetection, AntivirusDetectionActionType, etc. |
| SHA256 | SHA256 hash of the related file |
| AdditionalFields | JSON blob with ThreatName, ReportSource, Description, etc. |

---

## ATT&CK Kill Chain // Investigation Phases

| Phase | Name | Question |
|---|---|---|
| 01 | Public Exposure | What was leaked? |
| 02 | Scanning | Who found it? |
| 03 | Auth Baseline | Who tried to get in? |
| 04 | *(Redacted)* | — |
| 05 | *(Redacted)* | — |
| 06 | *(Redacted)* | — |
| 07 | *(Optional)* | — |

