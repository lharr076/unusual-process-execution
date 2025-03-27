# Threat Event (Unusual Process Execution)
**Unusual Process Execution and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Gain remote access to perform remote code execution(RCE)
2. The code execution deletes important company documents in folder nested in Documents folder

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table|
| **Purpose**| Used for detecting the folder deletion.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocesevents-table|
| **Purpose**| Used to detect the command line and PowerShell service launching.|

---

## Related Queries:
```kql
// Detect any changes made to the folder called Company Financial Records
DeviceFileEvents
| where FileName startswith "Company"

// Detect any unusual executions
DeviceProcessEvents
| where ProcessCommandLine contains "cmd.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

```

---

## Created By:
- **Author Name**: Larry Harris
- **Author Contact**: https://www.linkedin.com/in/larryharrisjr/
- **Date**: November 9, 2024

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
| 1.0         | Initial draft                  | `November 9, 2024`  | `Larry Harris Jr`   
