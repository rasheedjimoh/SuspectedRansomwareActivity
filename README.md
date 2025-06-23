## 🛑 Suspected Ransomware Activity - `pwncrypt.ps1`

### 🕒 Timeline Summary and Findings

#### 🔍 Extension Discovery on Endpoint
Upon investigation, it was discovered that **38 files** with the `.pwncrypt` extension were present on the `aarrjlab-vm` endpoint.

![image](https://github.com/user-attachments/assets/79b403ac-738a-4380-9580-ca5c6919999f)


```kql
DeviceFileEvents
| where DeviceName == "aarrjlab-vm" and FileName contains "pwncrypt"
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/20d4ff84-21f6-41d9-8bd7-9b14dfea5acb)


---

#### 📁 No Matching Processes Found
A search for processes with `pwncrypt` in the filename returned **no results**, indicating potential process tampering or cleanup.

![image](https://github.com/user-attachments/assets/f60deecb-e461-4efd-a66a-9b210d326826)


```kql
DeviceProcessEvents
| where DeviceName == "aarrjlab-vm" and FileName contains "pwncrypt"
| order by Timestamp desc
```

---

#### 📌 Timeline Pivot Based on First Detection
The timestamp of the first `.pwncrypt` file (`2025-02-09T16:13:45.1520847Z`) was used to analyze activity 3 minutes before and after the event.

![image](https://github.com/user-attachments/assets/01daf352-5720-45a5-9d14-b5f1a93adeb9)


```kql
let VMname = "aarrjlab-vm";
let SpecificTime = datetime(2025-02-09T16:13:45.1520847Z);
DeviceProcessEvents
| where DeviceName == VMname and Timestamp between (SpecificTime - 3m .. SpecificTime + 3m)
| order by Timestamp desc
| project Timestamp, DeviceName, ProcessCommandLine
```

Findings:
- Several processes executed around the time of `.pwncrypt` file creation.
- Powershell reached out to `raw.githubusercontent.com`, indicating likely **C2 communication**.
- File `pwncrypt.ps1` was executed via `cmd.exe` with `-ExecutionPolicy Bypass` from `C:\ProgramData`.

![image](https://github.com/user-attachments/assets/0cb56d82-09a5-4eda-85c7-7a9507f2198b)

---

### 🚨 Response Actions

- 🛡️ **Isolated** the endpoint.
- 🧪 **Collected** an investigative package.
- 🧼 **Ran** anti-malware scans.
- 🔒 **Returned** device to the network only after a clean scan.
- 🚫 **Blocked** C2 URL/IP used to download `pwncrypt.ps1`.
- 🛠️ **Analyzed** the script to understand behavior and intent.
- 🔍 **Searched** for similar IoCs across the environment.
- 🧠 **Used** threat intel platforms (e.g., VirusTotal, Hybrid Analysis, AnyRun) to verify malware signature.
- 📡 **Scanned** network for endpoints contacting `raw.githubusercontent.com`.
- 📝 **Documented** all actions for reporting and compliance.
- 🔁 **Shared** IoCs and updated internal threat intelligence (TI) feeds.
- ✅ **Helped** user recover encrypted files from backup.
- 🔐 **Enforced** PowerShell execution policies to disallow bypasses.

---

### 🎯 MITRE ATT&CK Framework TTPs

- **🛑 T1486** - Data Encrypted for Impact
- **💻 T1059.003** - Command & Scripting Interpreter: Windows Command Shell (`cmd.exe` execution)
- **💻 T1059.001** - PowerShell Execution with `-ExecutionPolicy Bypass`
- **🌐 T1105** - Ingress Tool Transfer (download from GitHub)
- **📡 T1071.001** - Web Protocols used for potential C2
- **📦 T1204.002** - User Execution of downloaded malicious script
- **🧼 T1070.004** - Indicator Removal (no logs in DeviceProcessEvents)
- **🛠️ T1562.001** - Impair Defenses: Bypassing policy for evasion
- **🔍 T1213.002** - Access to public code repositories (GitHub)
- **📤 T1041** - Potential Exfiltration Over C2 Channel

---

### 🧾 Conclusion & Recommendation
Although there was **no direct sign of exfiltration**, the following were confirmed:
- `.pwncrypt` files were created.
- Script `pwncrypt.ps1` was downloaded and run silently.
- Behavior consistent with ransomware or staged data encryption.

**🔁 Recommendation:**
Continue monitoring endpoint activity, reinforce PowerShell execution policies, and block public code repositories unless explicitly required.
