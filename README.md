<img width="400" src="https://github.com/lharr076/unusual-process-execution/blob/main/assests/powershell.jpg" alt="PowerShell image"/>

# Threat Hunt Report: Unusual Process Execution
- [Scenario Creation](https://github.com/lharr076/unusual-process-execution/blob/main/unusual_process_execution.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft PowerShell

##  Scenario

An employee logs into their machine and noticed in the Documents folder the financial records folder they created is missing along with all of the documents inside. The employee checked other locations on the device to be sure they did not move it elsewhere but still can not find it. The goal is to find what happened to the folder and analyze the incident. If any data is found, notify management.

### High-Level Insider Threat IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `Company` file events.
- **Check `DeviceProcessEvents`** for any signs of the command line or PowerShell usage.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "Company" in it and discovered what looks like the user "Training-vm-1186" created a Company Records folder in the Documents folder at `2025-03-26T20:48:18`.

**Query used to locate event:**

```kql
DeviceFileEvents
| where DeviceName startswith target_machine
| where FileName contains "Company"
| where ActionType in ("FileCreated", "FileRenamed")
| where Timestamp >=  datetime(2025-03-26)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/lharr076/unusual-process-execution/blob/main/assests/DeviceEvents_1.jpg">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for a `FileName` that equal to "cmd.exe" and `ProcessCommandLine` that contained the PowerShell string "Remove-Item". Based on the logs returned, at `2025-03-27T09:04:10`, the command line was opened and a PowerShell script was ran to delete the Documents folder.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == target_machine
| where FileName == "cmd.exe" and ProcessCommandLine contains "Remove-Item"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/lharr076/unusual-process-execution/blob/main/assests/DeviceProcessEvents_1.jpg">

---

## Chronological Event Timeline 

### 1. File/folder Created - End user created a company financial records

- **Timestamp:** `2025-03-26T20:48:14`
- **Event:** The user "Training-vm-1186" created a file/folder named `Command Financial Records` in the Documents folder.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Training-vm-1186\AppData\Roaming\Microsoft\Windows\Recent\Company Financial Records.lnk`

### 2. File/folder Deleted - Company Financial Records File/folder Deleted 

- **Timestamp:** `2025-03-27T09:04:10`
- **Event:** The Documents folder is deleted via PowerShell script.
- **Action:** Folder deletion detected.
- **Command:** `cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Remove-Item "C:\Users\Training-vm-1186\Documents" -Recurse -Force"`

---

## Summary

The VM "training-vm-118" experienced data loss of their Documents folder due to a PowerShell code being executed via command line. The user "Training-vm-1186" explained the creation of the file/folder "Company Financial Records" was created on `2025-03-26` and on `2025-03-27` the user noticed the file/folder was missing. After further analysis, it has been determined the entire Documents folder had been deleted an unusual process through the command line using a PowerShell script.

---

## Response Taken

Unusual Code Execution was confirmed on the endpoint `training-vm-118` by an `unknown threat actor`. The device was isolated, the user's direct manager was notified and system was backed up to a known good configuration.

---
