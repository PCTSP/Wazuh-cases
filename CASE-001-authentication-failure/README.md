[CASE-001-authentication-failure.md](https://github.com/user-attachments/files/31751205/CASE-001-authentication-failure.md)

# CASE-001 — Authentication Failure on Windows Server

## 1. Case Overview

| Field | Value |
|---|---|
| Case ID | CASE-001 |
| Category | Authentication / Windows Security |
| Severity | Low |
| Classification | Suspicious Activity — Inconclusive |
| Endpoint | DC01 |
| Event ID | 4625 |
| Wazuh Rule | 60122 |
| Account targeted | Administrator |
| Investigation status | Closed |

---

## 2. Executive Summary

During monitoring of the Windows endpoint **DC01**, Wazuh identified multiple failed authentication events targeting the **Administrator** account.

Four Event ID **4625** events were identified within approximately **28 seconds**.

Initial indicators could suggest repeated authentication attempts. However, correlation with the available Windows telemetry did not provide sufficient evidence to classify the activity as brute force or as a confirmed compromise.

The events reported:

- Source IP: `127.0.0.1`
- Workstation: `DC01`
- Logon Type: `2` (Interactive)
- Process: `C:\Windows\System32\svchost.exe`
- Process ID: `0x590` (`1424`)
- Subject: `DC01$`
- Subject SID: `S-1-5-18` (SYSTEM)
- Target account: `Administrator`
- Authentication package: `Negotiate`
- Status: `0xc000006d`
- Substatus: `0xc000006a`

The investigation was closed as **low-severity suspicious activity with insufficient evidence for definitive attribution**.

---

## 3. Detection

### Detection source

**Wazuh Security Monitoring**

### Detection rule

- Rule ID: `60122`
- Description: `Logon Failure - Unknown user or bad password`
- Windows Event ID: `4625`

### Observed activity

Four failed authentication events were identified:

| Event | Approx. time |
|---|---|
| 1 | 10:21:01 |
| 2 | 10:21:04 |
| 3 | 10:21:15 |
| 4 | 10:21:28 |

The events occurred over a short period, making correlation necessary before determining whether the activity represented malicious behavior.

---

## 4. Initial Hypothesis

### Hypothesis H1 — Brute-force or password-guessing activity

**Status: Not confirmed**

The short sequence of authentication failures initially justified investigation for possible password-guessing behavior.

However, the available evidence did not show:

- multiple external source addresses;
- attempts against multiple accounts;
- a successful authentication immediately following the failures;
- explicit credential usage;
- sufficient process-creation telemetry to identify the initiating process.

Therefore, the evidence was insufficient to classify the activity as brute force.

---

## 5. Event Analysis

### 5.1 Authentication failure — Event ID 4625

The relevant Windows event showed:

```text
Event ID:              4625
Target User:           Administrator
Target Domain:         LAB
Source IP:             127.0.0.1
Workstation:           DC01
Logon Type:            2
Authentication Package: Negotiate
Process Name:          C:\Windows\System32\svchost.exe
Process ID:            0x590
Subject User:          DC01$
Subject SID:           S-1-5-18
Status:                0xc000006d
Substatus:             0xc000006a
```

### Interpretation

The event reports the loopback address `127.0.0.1` as the source and identifies `DC01` as the workstation.

The subject is associated with the SYSTEM security context, while the target account is `Administrator`.

This makes a **local system/service-related activity** a plausible hypothesis, but the evidence does not identify the exact service responsible.

---

## 6. Correlation Performed

### Event ID 4624 — Successful logon

Successful authentication events were searched and analyzed.

A 4624 event was found, but it represented a **machine-account network logon by `DC01$`**, occurring significantly later than the 4625 sequence.

Therefore, it was **not considered a successful authentication corresponding to the investigated failures**.

### Event ID 4648 — Explicit credential usage

No relevant Event ID 4648 events were found during the investigated time window.

**Result:** No additional evidence of explicit credential usage.

### Event ID 4776 — Credential validation

No relevant Event ID 4776 events were found during the investigated time window.

**Result:** No additional credential-validation evidence was available.

### Event ID 4688 — Process creation

No relevant Event ID 4688 events were found during the investigated time window.

This is treated as a **visibility limitation**, not proof that no process was executed.

---

## 7. Process Investigation

The event referenced:

```text
svchost.exe
PID: 1424
```

The current process investigation showed:

```text
Process: svchost.exe
PID: 1424
Start time: 09:44:09
Command line: C:\Windows\System32\svchost.exe -k netsvcs -p
Parent PID: 712
```

The process hosts multiple Windows services, including:

- `Schedule` — Task Scheduler
- `UserManager` — User Manager
- `Winmgmt` — Windows Management Instrumentation
- `Appinfo` — Application Information
- `UsoSvc` — Update Orchestrator Service
- `iphlpsvc` — IP Helper
- `TokenBroker`
- `WpnService`
- `ShellHWDetection`
- `Themes`

The process had started before the authentication failures, making the temporal relationship **plausible**.

However:

> A PID alone does not provide sufficient forensic evidence to prove that a specific service caused the authentication failures.

The investigation therefore did not attribute the activity to any individual service.

---

## 8. Evidence Matrix

| Evidence | Observation | Assessment |
|---|---|---|
| 4625 | Four failures against Administrator | Confirmed |
| Source IP | `127.0.0.1` | Local/loopback origin reported |
| Logon Type | `2` | Interactive |
| Process | `svchost.exe` | Relevant process reference |
| Subject | `DC01$ / SYSTEM` | System context |
| 4624 | Later machine-account logon | Not correlated |
| 4648 | Not found | No additional evidence |
| 4776 | Not found | No additional evidence |
| 4688 | Not found | Visibility limitation |
| svchost PID | `1424` | Plausible temporal correlation |
| Specific service | Not determined | Attribution inconclusive |

---

## 9. MITRE ATT&CK Assessment

The Wazuh event contained a MITRE ATT&CK mapping.

The mapping was **not accepted automatically as proof of attacker behavior**.

The available evidence did not establish that the event represented an ATT&CK technique being actively used by an adversary.

This case therefore demonstrates an important SOC principle:

> **SIEM rule enrichment is an investigative lead, not a substitute for analyst validation.**

A future iteration of the lab can improve telemetry and validate ATT&CK mappings against stronger behavioral evidence.

---

## 10. Final Classification

**Severity:** Low

**Classification:**

> **Suspicious Activity — Inconclusive**

### Rationale

The authentication failures were real and repeatable in the Windows Security logs, but the available evidence does not establish:

- brute-force activity;
- external attack origin;
- successful compromise;
- malicious process execution;
- explicit credential abuse.

A local Windows component or service using invalid credentials remains a plausible explanation.

---

## 11. Investigation Limitations

The investigation was constrained by the telemetry currently collected by the lab.

The main limitations were:

1. No relevant Event ID 4648.
2. No relevant Event ID 4776.
3. No relevant Event ID 4688.
4. The `svchost.exe` process hosts multiple services.
5. The available evidence does not establish which service initiated the authentication attempt.
6. The PID provides useful temporal correlation but is not, by itself, definitive forensic attribution.

These limitations are documented intentionally rather than being treated as missing conclusions.

---

## 12. Recommended Future Improvements

For a future detection-engineering iteration, the lab could be enhanced with:

- Windows Process Creation auditing;
- command-line process logging;
- Sysmon telemetry;
- additional Task Scheduler visibility;
- improved correlation rules in Wazuh;
- validation of ATT&CK mappings against observed behavior.

These improvements are **out of scope for CASE-001** and should be treated as future lab enhancements.

---

## 13. Analyst Conclusion

> Four failed authentication attempts against the `Administrator` account were detected on DC01 within approximately 28 seconds. The events originated from the loopback address `127.0.0.1`, used Logon Type 2, and referenced `svchost.exe` running under a SYSTEM-related context.
>
> Correlation with available authentication and process telemetry did not identify evidence sufficient to confirm brute-force activity, external attack, or compromise. A successful 4624 event found during the investigation was associated with the machine account `DC01$` and occurred outside the relevant time window.
>
> The referenced `svchost.exe` instance was investigated and found to host multiple Windows services. Although its start time preceded the authentication failures, the available telemetry was insufficient to identify the responsible service.
>
> The case is therefore classified as **Low / Suspicious Activity — Inconclusive** and closed without further changes to the laboratory. The investigation demonstrates the importance of evidence-based correlation, explicit documentation of telemetry limitations, and avoiding premature attribution of security events.

---

## 14. Skills Demonstrated

This case demonstrates practical experience with:

- Wazuh SIEM;
- Windows Security Event Logs;
- Event ID 4625 analysis;
- Event ID 4624 correlation;
- Event IDs 4648 and 4776 investigation;
- Event ID 4688 visibility assessment;
- authentication investigation;
- process/service correlation;
- hypothesis-driven investigation;
- evidence-based classification;
- MITRE ATT&CK validation;
- SOC analyst documentation;
- identification of telemetry gaps.

---

## 15. Evidence

Recommended repository structure:

```text
cases/
└── CASE-001-authentication-failure/
    ├── README.md
    └── evidence/
        ├── wazuh-4625.png
        └── svchost-investigation.png
```

Screenshots should be sanitized before publication. Do not include passwords, tokens, API keys, private IPs that you do not want publicly exposed, or other sensitive information.
