# Threat Event (Suspicious Firefox Behavior)
**Unusual Firefox Behavior Indicating Potential Web Shell Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download and Install Firefox
The attacker downloads Firefox from an official source, but the installation is carried out in a non-standard manner, possibly silently or via script.
   - Download Firefox: `https://www.mozilla.org/firefox/download/`
   - Silent install command: `firefox-installer.exe /s`

2. Launch Firefox with Abnormal Command-Line Arguments
The attacker starts Firefox using command-line arguments that indicate it may be running in an unusual or potentially malicious context.
   - Command-line arguments:
   `firefox.exe --new-instance --no-remote-profile "C:\Temp\FirefoxProfile"`

3.  Navigate to Suspicious Web Shell Site
The attacker accesses a site that may host or serve web shells.
Example suspicious URL accessed by Firefox:
   - `http://example.com/shell.php`
  
4. Interact with the Web Shell
The attacker interacts with the web shell, potentially to upload, download, or execute malicious code. Firefox might also be used to access further malicious resources.
   - Execute malicious JavaScript or shell commands on the target server.
   - Potential exfiltration of data or system compromise.


5. Download Malicious Files
Using Firefox, the attacker downloads a potentially malicious file to the local system.
   - Malicious file: `exploit.zip` or a payload such as `shell.exe`

6. Clean Up Activity
After completing the malicious activity, the attacker deletes certain files or logs to cover their tracks.
   - Delete downloaded files and potentially the profile created for malicious browsing.


---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table|
| **Purpose**| Detects unusual execution of Firefox (e.g., command-line arguments, web shell access). |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Detects download of potentially malicious files (e.g., `shell.exe`, `exploit.zip`). |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Detects unusual network connections, particularly those made by Firefox to malicious sites or unexpected external IPs. |

---

## Related Queries:
```kql
// Detect unusual Firefox process execution (non-standard flags or profiles)
DeviceProcessEvents
| where FileName  =="firefox.exe"
| where ProcessCommandLine contains "--no-remote" and ProcessCommandLine contains "-profile"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine, AccountName


// Detect Firefox downloading a potentially malicious file (e.g., .zip, .exe)
DeviceFileEvents
| where FileName in~ ("shell.exe")
| where ActionType == “FileCreated”
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName


// Detect suspicious network connections initiated by Firefox 
DeviceNetworkEvents
| where  DeviceName == "davarthreathunt"
| where InitiatingProcessFileName == "firefox.exe"
| where isnotempty(RemoteUrl)
| project Timestamp, RemoteUrl, InitiatingProcessAccountName, DeviceName


// Detect file cleanup activity (deletion of suspicious files like "shell.exe")
DeviceFileEvents
| where FileName in~ ("shell.exe")
| where ActionType == "FileDeleted"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessAccountName

```

---

## Created By:
- **Author Name**: Pavan Kumar Davar
- **Author Contact**: https://www.linkedin.com/in/pavan-kumar-davar/
- **Date**: April 10, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April  14, 2025`  | `Pavan Kumar Davar`   
