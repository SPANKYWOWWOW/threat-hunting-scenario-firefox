![Screenshot_2025-04-14_201227-removebg-preview](https://github.com/user-attachments/assets/b057a1f4-3bed-4b0a-8994-51f2fb187b35)
# Threat Hunt Report: Suspicious Firefox Behavior
- [Scenario Creation](https://github.com/SPANKYWOWWOW/threat-hunting-scenario-firefox/blob/main/threat-hunting-scenario-firefox-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- FireFox Browser

##  Scenario
An internal security alert was triggered after an endpoint showed signs of abnormal browser usage. The user, a developer, had downloaded and silently installed Firefox using a script rather than through approved software deployment tools. Shortly after, command-line telemetry revealed that Firefox was launched with flags like `--no-remote` and `-profile`, commonly used to isolate browsing sessions — a behavior often seen in evasion or malicious contexts.
Network logs indicated that the browser established a connection to a suspicious domain `(example.com/shell.php)`, which is known to host web shells. A file named shell.exe was downloaded during this session and then quickly deleted from the system, suggesting an attempt to cover tracks. This behavior aligned with known TTPs (tactics, techniques, and procedures) used in fileless malware attacks and lateral movement via browser-based payloads.
The device was flagged for containment, and the user account was escalated for further investigation.

### High-Level FireFox IoC Discovery Plan

- Detect Suspicious Firefox Execution :
  Identify use of `firefox.exe` launched with unusual command-line arguments like `--no-remote`, `--new-instance`, or `-profile` via `DeviceProcessEvents`.

- Monitor Malicious File Downloads :
 Use `DeviceFileEvents` to detect dropped files such as `shell.exe`, `exploit.zip`, or other suspicious `.exe/.zip` payloads.

- Track Network Connections Made by Firefox :
 Check `DeviceNetworkEvents` for connections from Firefox to suspicious domains (e.g., /`shell.php`, unknown external IPs).

- Detect Cleanup Activities :
 Look for deletion of known malicious files or temporary Firefox profile folders via `DeviceFileEvents` with `ActionType == "Deleted"`.

- Correlate with User and Device Info :
 Pivot on `InitiatingProcessAccountName`, `DeviceName`, and `RemoteIP` to identify affected users or endpoints and assess impact.

---

## Steps Taken

### 1.  Investigated Firefox Execution with Suspicious Arguments:

Queried DeviceProcessEvents to identify instances where `'firefox.exe'` was launched using `'--no-remote'` and `'-profile'` flags, which indicate isolated or potentially malicious activity.
**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName  =="firefox.exe"
| where ProcessCommandLine contains "--no-remote" and ProcessCommandLine contains "-profile"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine, AccountName


```
![image](https://github.com/user-attachments/assets/2b0673c3-5830-4cf7-8bdf-f13d42867f0e)



---

### 2. Searched for Malicious File Creation Events:

Queried DeviceFileEvents to look for dropped files like `'shell.exe'`, which could indicate delivery of a malicious payload.

**Query used to locate event:**

```kql

DeviceFileEvents
| where FileName in~ ("shell.exe")
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName


```
![image](https://github.com/user-attachments/assets/8ce038cf-b5f3-41df-9e3e-c4e07ebedb40)



---

### 3. Monitored Suspicious Network Access via Firefox:

Queried DeviceNetworkEvents to detect connections from `'firefox.exe'` to suspicious domains like `'example.com'.`


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where  DeviceName == "davarthreathunt"
| where InitiatingProcessFileName == "firefox.exe"
| where isnotempty(RemoteUrl)
| project Timestamp, RemoteUrl, InitiatingProcessAccountName, DeviceName


```
![image](https://github.com/user-attachments/assets/66e91755-c3d7-4b6a-b898-a51874daec86)



---

### 4.  Checked for Deletion of Malicious Files (Cleanup Behavior):

Used DeviceFileEvents to find instances where `'shell.exe'` was deleted, indicating possible evidence hiding or cleanup activity.


**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName in~ ("shell.exe")
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessAccountName


```
![image](https://github.com/user-attachments/assets/d2c913d2-2ec8-4f35-819f-0811d488abcd)



---

## Chronological Event Timeline 

`2025-04-14T21:47:03.7403314Z :`           Firefox launched with '--no-remote' and custom profile – potential abnormal usage.
`2025-04-14T21:49:07.2877037Z :`	         File 'shell.exe' created on disk (payload download).
`2025-04-14T21:47:55.0595696Z :`         Network connection to 'example.com' established via Firefox.
`2025-04-14T21:49:07.1538465Z :`         'shell.exe' file was deleted (possible cleanup activity).

---

## Summary

During this hunt, we identified abnormal Firefox usage characterized by command-line arguments that launched Firefox in isolated mode. We observed potential indicators of compromise including the download and deletion of a suspicious file `('shell.exe')` and a connection to a known suspicious domain. These actions align with behaviors commonly associated with web shell activity or malware deployment. Appropriate containment actions should be taken, including isolating the device and reviewing associated accounts and activity.

---

## Response Taken

Suspicious Firefox activity was confirmed on endpoint `DavarThreathunt` by the use `labuser007`. The device showed evidence of unauthorized execution flags, potential payload download `(shell.exe)`, and a connection to a known suspicious domain. Immediate action was taken to isolate the device from the network, and an alert was escalated to the SOC team. The user’s account was temporarily disabled, and a full forensic review was initiated to determine scope of compromise. All related IoCs were added to the detection rule set to prevent recurrence across the environment.

---
