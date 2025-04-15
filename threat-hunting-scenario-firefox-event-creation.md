# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - **WARNING: The links to onion sites change a lot and these have changed. However if you connect to Tor and browse around normal sites a bit, the necessary logs should still be created:**
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```

6. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.

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
