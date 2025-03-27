<img width="400" src="https://github.com/lharr076/insider-threat-scenario/blob/main/assests/insider_threat_image.jpg" alt="Insider Threat image"/>

# Threat Hunt Report: Unusual Process Execution
- [Scenario Creation](https://github.com/lharr076/unusual-process-execution/blob/main/unusual_process_execution.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft PowerShell

##  Scenario

An employee logs into their machine and noticed in the Documents folder the financial records folder they created is missing along with all of the documents inside. The employee checked other locations on the device to be sure they did not move it elseware but still can not find it. The goal is to find what happened to the folder and analyze the incident. If any data is found, notify management.

### High-Level Insider Threat IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `Company` file events.
- **Check `DeviceProcessEvents`** for any signs of the command line or PowerShell usage.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "Company" in it and discovered what looks like the user "Training-vm-1186" created a Company Records folder in the Documents folder at `2025-03-26T20:48:18`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName startswith target_machine
| where FileName contains "Company"
| where ActionType in ("FileCreated", "FileRenamed")
| where Timestamp >=  datetime(2025-03-26)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/lharr076/insider-threat-scenario/blob/main/assests/DeviceFileEvents.jpg">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "olk.exe". Based on the logs returned, at `2025-03-25T05:48:35`, an employee on the "training-vm-118" device ran `olk.exe` which is Microsoft Outlook outside operation hours of the company. Between `2025-03-25T10:34:32` and `2025-03-25T10:37:09` multiple Outlook processes are created possibly signaling preparation for exfiltration. At `2025-03-25T18:40:54` the `olk.exe` process is created again afterhours.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == target_machine
| where FileName == "olk.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/lharr076/insider-threat-scenario/blob/main/assests/DeviceProcessEvents.jpg">

---

## Chronological Event Timeline 

### 1. File Created - PII Data Text File

- **Timestamp:** `2025-03-25T10:33:01`
- **Event:** The user "Training-vm-1186" created a file named `PII Data.txt` to the Documents folder.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Training-vm-1186\Documents\Fake PII Data.txt`

### 2. Folder Created - PII Folder 

- **Timestamp:** `2025-03-25T10:33:34`
- **Event:** The user "Training-vm-1186" created folder `PII` on the desktop and moved the `PII Data.txt` file into the folder.
- **Action:** Folder creation detected.
- **File Path:** `C:\Users\Training-vm-1186\Desktop\Fake PII\Fake PII Data.txt`

### 3. Zip File Creation - PII.zip

- **Timestamp:** `2025-03-25T10:41:03`
- **Event:** User "Training-vm-1186" created zip file `PII.zip` in Temp folder in attempt to hide actions. 
- **Action:** Zip file created.
- **File Path:** `C:\Windows\Temp\Fake PII.zip`

### 4. Email Use Outside Operational Hours - Microsoft Outlook Activity

- **Timestamp:** `2025-03-25T05:48:35`
- **Event:** An email operation by user "Training-vm-1186" was established using `olk.exe`, confirming Microsoft Outlook activity after hours.
- **Action:** Connection success.
- **Process:** `olk.exe`
- **File Path:** `C:\Program Files\WindowsApps\Microsoft.OutlookForWindows_1.2025.312.0_x64__8wekyb3d8bbwe\olk.exe`

### 5. Additional Email Activity - Microsoft Outlook Activity

- **Timestamps:** From `2025-03-25T10:34:32` to `2025-03-25T10:37:09`
- **Event:** Additional email activity was conducted, indicating ongoing activity by user "Training-vm-1186" through Microsoft Outlook.
- **Action:** Microsoft Outlook login successful.

### 6. Additional Email Activity - Microsoft Outlook Activity

- **Timestamps:** `2025-03-25T18:40:54`
- **Event:** An email operation by user "Training-vm-1186" was established using `olk.exe`, confirming Microsoft Outlook activity after hours.
- **Action:** Microsoft Outlook login successful.
- **File Path:** `C:\Program Files\WindowsApps\Microsoft.OutlookForWindows_1.2025.319.100_x64__8wekyb3d8bbwe\olk.exe`
---

## Summary

The user "Training-vm-1186" on the "training-vm-118" performed data exfiltration. They proceeded to create a PII file in notepad called `PII Data.txt`, created a folder called `PII` on the desktop , moved and created a zip file in the Windows Temp folder, and exfiltrate via Microsoft Outlook email. This sequence of activities indicates that the user actively copied and exfiltrated company PII data via Microsoft Outlook.

---

## Response Taken

Data exfiltration was confirmed on the endpoint `training-vm-118` by the user `Training-vm-1186`. The device was isolated, and the user's direct manager was notified.

---
