# Threat Hunt Report: External RDP Compromise — Signals Before the Noise
<img width="709" height="418" alt="image" src="https://github.com/user-attachments/assets/ed93ddd9-a7e3-44ba-b850-7974f13d91a4" />

- [Proactive Hunt Brief](./hunt-03-brief.md)

## Platforms and Languages Leveraged

- Windows 10 Virtual Machines (Microsoft Azure)
- SIEM Platform: Microsoft Sentinel (`law-cyber-range`)
- EDR Telemetry: Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- GeoIP Enrichment via external CSV dataset

---

## Scenario

A cloud engineer at PHTG posted a photo on LinkedIn celebrating the rollout of a new internal service — HealthCloud. The photo showed their workstation with an Azure portal session open, unintentionally exposing the public IP address, hostname, OS, and virtual network details of a production VM (`azwks-phtg-02`). No incident was declared. No alerts had fired. The task was to determine whether that exposure was noticed, whether it was acted on, and whether an attacker had already moved.

### High-Level Hunt Plan

- **OSINT Phase** — Extract infrastructure details from the LinkedIn photo and Azure portal view.
- **Check `DeviceNetworkEvents`** — Identify scanning activity against the exposed public IP on port 3389.
- **Check `DeviceLogonEvents`** — Identify authentication attempts, failure patterns, and successful logins. Enrich source IPs with GeoIP data.
- **Check `DeviceProcessEvents`** — Identify post-access operator behaviour and payload execution.
- **Check `DeviceFileEvents`** — Track the payload through its rename chain to its final resting place.
- **Check `DeviceEvents`** — Retrieve Defender's classification of the payload and observe AV state changes.

---

## Steps Taken

### 1. OSINT — What Was Exposed

Reviewed the LinkedIn post and the visible Azure portal screenshot. The photo exposed the following details about VM `azwks-phtg-02`:

| Field | Value |
|---|---|
| Hostname | `azwks-phtg-02` |
| Public IP | `74.249.82.162` |
| Private IP | `10.0.0.152` |
| OS | Windows 10 Enterprise |
| Region | East US 2, Zone 1 |
| VNet/Subnet | Cyber-Range-VNet / Cyber-Range-Subnet |
| VM Created | 12/10/2025, 3:08 AM UTC |
| HealthCloud Rollout | 11 December 2025 |

The public IP address was the critical element — it made the VM directly addressable from the internet.

---

### 2. Scanning Activity — `DeviceNetworkEvents`

Queried for inbound connections on port 3389 (RDP) from public IPs.

**Query used:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName contains "azwks-phtg-02"
| where LocalPort == 3389
| where RemoteIPType == "Public"
| count
```

- **197** total network events on port 3389 from public IPs.
- **173** unique source IPs targeted the exposed service.
- **57** source IPs showed more than one ActionType — both attempted and accepted connections, indicating a higher-confidence scanning class.
- GeoIP enrichment revealed **11 distinct countries** associated with this RDP scanning activity.

---

### 3. Authentication Activity — `DeviceLogonEvents`

Queried for externally sourced authentication events on the device.

**Query used:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName contains "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| summarize count() by ActionType
| order by count_ desc
```

- **675** total RDP-related authentication events from public IPs.
- Dominant outcome: **`LogonFailed`** (646 events).
- Most common failure reason: **`InvalidUserNameOrPassword`** — classic credential brute force.
- **29 successful** logon events recorded.
- GeoIP enrichment: **17 countries** associated with authentication attempts.
- **2 countries** had at least one successful authentication: **United States** and **Uruguay**.

PHTG operates exclusively in the United States. **Uruguay** was immediately flagged as anomalous.

---

### 4. Attacker Access — Uruguay Logons

Filtered successful logons to Uruguay source IPs only.

**Query used:**

```kql
let GeoTable = externaldata(network:string, geoname_id:long, continent_code:string, continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName contains "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| project TimeGenerated, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
```

| Field | Value |
|---|---|
| Account | `vmadminusername` |
| Successful Sessions | 23 |
| First Source IP | `173.244.55.131` |
| Second Source IP | `173.244.55.128` |
| First Logon | 12/12/2025, 5:47:45 AM UTC |
| First Interactive Session | 12/13/2025, 9:31:20 AM UTC |

Both IPs fall within the same `/24` subnet — consolidated attacker infrastructure.

---

### 5. Post-Access Behaviour — `DeviceProcessEvents`

Scoped process events to after the first Uruguay logon and filtered by the compromised account.

**First notable process:**

```
notepad.exe — launched at 12/12/2025, 1:35:54 PM UTC from powershell.exe
Command: "NOTEPAD.EXE" C:\Users\vmAdminUsername\Documents\PHTG\notes_sarah.txt
```

The attacker opened **`notes_sarah.txt`** — internal documentation belonging to the engineer who made the LinkedIn post. This file likely contained internal service details that reduced the attacker's effort.

---

### 6. Payload Delivery — `DeviceFileEvents`

Tracked the payload through its full rename chain using the file hash.

**SHA256:** `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695`

| Timestamp | ActionType | FileName | Location |
|---|---|---|---|
| 12/12 2:11 PM | FileRenamed | `Sarah_Chen_Notes.Txt` | Downloads |
| 12/12 2:13 PM | FileRenamed | `Sarah_Chen_Notes.Txt` | Documents\PHTG |
| 12/12 2:14 PM | FileRenamed | `Sarah_Chen_Notes.exe.Txt` | Documents\PHTG |
| 12/12 2:18 PM | FileCreated | `Sarah_Chen_Notes.exe.Txt` | Documents\PHTG |
| 12/12 2:18 PM | FileRenamed | `Sarah_Chen_Notes.exe` | Documents\PHTG |
| 12/13 10:14 AM | FileRenamed | `Sarah_Chen_Notes.exe` | C:\ProgramData\PHTG\HealthCloud |
| 12/13 10:16 AM | FileRenamed | `PHTG.exe` | C:\ProgramData\PHTG\HealthCloud |

**Double-extension evasion:** The file was briefly named `Sarah_Chen_Notes.exe.Txt` — appearing as a text file while containing an executable. The final name `PHTG.exe` placed inside the legitimate HealthCloud directory was designed to blend with expected service infrastructure.

---

### 7. Payload Execution & Defense Evasion — `DeviceEvents` + `DeviceProcessEvents`

Windows Defender detected and quarantined the payload three times between 14:11 and 14:17 on 12 December. Shortly after, Defender was switched to **Passive Mode** — allowing detections to be logged but removing the ability to block or quarantine. The payload then executed successfully.

**Defender Classification:** `Trojan:Win32/Meterpreter.RPZ!MTB`  
**Malware Family:** **Meterpreter** (Metasploit post-exploitation framework)

**Execution phases:**

| Phase | FileName | Initiating Process |
|---|---|---|
| Phase 1 | `Sarah_Chen_Notes.exe` | Direct execution |
| Phase 2 | `PHTG.exe` | `cmd.exe` via `C:\ProgramData\PHTG\HealthCloud\Launch.bat` |

---

### 8. C2 Communication — `DeviceNetworkEvents`

Queried network events initiated by the payload process hash.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName contains "azwks-phtg-02"
| where InitiatingProcessSHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where RemoteIPType == "Public"
| project TimeGenerated, RemoteIP, RemotePort, ActionType
```

| Field | Value |
|---|---|
| C2 IP | `173.244.55.130` |
| C2 Port | `4444` (default Metasploit listener) |
| C2 Country | Uruguay, South America |
| Outcome | `ConnectionFailed` (Defender interference) |

The C2 IP falls in the same `/24` as the attacker's RDP IPs (`173.244.55.128`, `.130`, `.131`) — all infrastructure consolidated in Uruguay.

---

## Chronological Attack Timeline

### 1. Public Exposure
- **Date:** 11–12 December 2025
- **Event:** PHTG cloud engineer posts LinkedIn photo exposing Azure VM details including public IP `74.249.82.162` and hostname `azwks-phtg-02`.

### 2. Scanning
- **Date:** 9–12 December 2025
- **Event:** 173 unique public IPs scan port 3389. 57 receive TCP responses. Scanners originate from 11 countries.

### 3. Brute Force
- **Date:** 12 December 2025
- **Event:** 646 failed RDP authentication attempts against `vmadminusername` using `InvalidUserNameOrPassword`. 

### 4. Initial Access
- **Timestamp:** 12/12/2025, 5:47:45 AM UTC
- **Event:** First successful logon from `173.244.55.131` (Uruguay) using account `vmadminusername`.

### 5. Reconnaissance
- **Timestamp:** 12/12/2025, 1:35:54 PM UTC
- **Event:** Attacker opens `notes_sarah.txt` via `notepad.exe`, reading internal PHTG documentation.

### 6. Payload Delivery
- **Timestamp:** 12/12/2025, ~2:11 PM UTC
- **Event:** Meterpreter payload downloaded as `Sarah_Chen_Notes.Txt.crdownload`, renamed through double-extension evasion chain.

### 7. Defense Evasion
- **Timestamp:** 12/12/2025, ~2:14–2:17 PM UTC
- **Event:** Defender quarantines payload three times. Attacker switches Defender to **Passive Mode**. Payload executes as `Sarah_Chen_Notes.exe`.

### 8. Persistence
- **Timestamp:** 12/13/2025, ~10:14–10:16 AM UTC
- **Event:** Payload renamed to `PHTG.exe` and moved to `C:\ProgramData\PHTG\HealthCloud\`. Batch file `Launch.bat` created in same directory.

### 9. C2 Callback
- **Timestamp:** 12/12/2025, 2:19 PM UTC / 12/13/2025, ~10:13–10:22 AM UTC
- **Event:** `PHTG.exe` attempts outbound connection to `173.244.55.130:4444` (Metasploit listener, Uruguay).

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Target Host | `azwks-phtg-02` |
| Exposed Public IP | `74.249.82.162` |
| Attacker IP 1 | `173.244.55.131` |
| Attacker IP 2 | `173.244.55.128` |
| C2 IP | `173.244.55.130` |
| C2 Port | `4444` |
| C2 Country | Uruguay, South America |
| Compromised Account | `vmadminusername` |
| Payload SHA256 | `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` |
| Payload (Phase 1) | `Sarah_Chen_Notes.exe` |
| Payload (Phase 2) | `PHTG.exe` |
| Persistence Script | `C:\ProgramData\PHTG\HealthCloud\Launch.bat` |
| Malware Family | `Trojan:Win32/Meterpreter.RPZ!MTB` |
| Sensitive File Accessed | `C:\Users\vmAdminUsername\Documents\PHTG\notes_sarah.txt` |

---

## ATT&CK Mapping

| Tactic | Technique | Detail |
|---|---|---|
| Reconnaissance | T1593.001 — Social Media | LinkedIn post exposed VM infrastructure |
| Initial Access | T1110.001 — Brute Force: Password Guessing | 646 failed attempts before success |
| Initial Access | T1021.001 — Remote Services: RDP | RDP from Uruguay IPs |
| Defense Evasion | T1562.001 — Impair Defenses: Disable AV | Defender switched to Passive Mode |
| Defense Evasion | T1036.007 — Masquerading: Double Extension | `Sarah_Chen_Notes.exe.Txt` |
| Persistence | T1053 / T1547 | `Launch.bat` in HealthCloud directory |
| C2 | T1571 — Non-Standard Port | Meterpreter over port 4444 |
| Collection | T1005 — Data from Local System | `notes_sarah.txt` opened via Notepad |

---

## Response Taken

Compromise confirmed on `azwks-phtg-02` via external RDP brute force from Uruguay (`173.244.55.128/131`). The device was identified for isolation. The payload `PHTG.exe` (`Trojan:Win32/Meterpreter.RPZ!MTB`) was flagged for removal. The `vmadminusername` account was flagged for credential reset. Management and the IR team were notified. The HealthCloud directory was flagged for integrity review to separate legitimate service files from attacker-planted artifacts.
