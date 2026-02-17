\# pfsense-to-splunk-rdp-segmentation-detection



Status: Completed  

Security Control Validated: Network Segmentation (ATTACKNET → LAN)  

Detection Type: Cross-layer Correlation (Firewall + Endpoint)  

Mapped Techniques: T1110, T1021.001  



---



\*\*Phase 2 — Experiment 1 | Network Segmentation Validation + RDP Attack Telemetry Correlation (pfSense + Windows + Splunk)\*\*



\## Executive Summary



This experiment validates network segmentation enforcement and detection engineering correlation within a Blue Team home lab environment. A Kali attacker system (ATTACKNET) generated failed RDP authentication attempts against a Windows endpoint (LAN). Telemetry was captured at two layers:



\- \*\*Network layer:\*\* pfSense firewall filterlog  

\- \*\*Endpoint layer:\*\* Windows Security Event ID 4625  



Both data sources were ingested into \*\*Splunk Enterprise\*\* for centralized analysis.



The experiment confirmed that RDP traffic was temporarily allowed for controlled testing, enabling measurable attack telemetry. A blanket allow rule on the OPT1 interface was then identified and removed to restore proper segmentation. After enforcement, pfSense logged \*\*BLOCK\*\* events for TCP/3389 and Windows no longer generated new 4625 failures from the attacker source.



This demonstrates both prevention and visibility across security layers.



---



\## What This Proves



\- \*\*Segmentation enforcement works:\*\* ATTACKNET → LAN traffic is blocked by policy (pfSense BLOCK on TCP/3389).

\- \*\*Controlled exception testing is measurable:\*\* Temporary RDP allowance produces correlated firewall and endpoint telemetry.

\- \*\*Cross-layer correlation strengthens detection:\*\* Firewall PASS/BLOCK events align with Windows authentication failures (Event ID 4625).

\- \*\*Configuration weaknesses are detectable:\*\* An unintended blanket allow rule on OPT1 was discovered and removed, restoring intended security posture.

\- \*\*Security controls can be validated through telemetry:\*\* Enforcement was verified by observing BLOCK events and the absence of new 4625 failures post-remediation.



---



\## Lab Architecture



\### Network Segments



\- \*\*LAN:\*\* `192.168.10.0/24`  

&nbsp; - Windows endpoint: `192.168.10.2`



\- \*\*ATTACKNET (OPT1):\*\* `192.168.20.0/24`  

&nbsp; - Kali attacker: `192.168.20.100`



\### Stack



\- \*\*pfSense Firewall\*\* (WAN / LAN / OPT1-ATTACKNET)

\- \*\*Splunk Enterprise on Ubuntu\*\* (indexing, search, dashboards)

\- \*\*Windows Endpoint\*\* with Splunk Universal Forwarder

\- \*\*Kali Linux Attacker VM\*\*



---



\## Diagram (Mermaid)



```mermaid

flowchart LR

&nbsp; subgraph ATTACKNET\["ATTACKNET (192.168.20.0/24)"]

&nbsp;   K\["Kali Attacker<br/>192.168.20.100"]

&nbsp; end



&nbsp; subgraph FW\["pfSense Firewall"]

&nbsp;   OPT1\["OPT1: ATTACKNET<br/>Ingress Rules"]

&nbsp;   LANIF\["LAN: 192.168.10.0/24"]

&nbsp; end



&nbsp; subgraph LAN\["LAN (192.168.10.0/24)"]

&nbsp;   W\["Windows Endpoint<br/>192.168.10.2<br/>Security Log: Event ID 4625"]

&nbsp; end



&nbsp; subgraph SIEM\["Splunk Enterprise (Ubuntu)"]

&nbsp;   S\["Splunk Index/Search<br/>Correlation SPL"]

&nbsp; end



&nbsp; K -- "RDP attempts (TCP/3389)" --> OPT1

&nbsp; OPT1 -- "PASS (temporary allow)" --> LANIF --> W

&nbsp; OPT1 -- "BLOCK (after enforcement)" --> LANIF



&nbsp; OPT1 -- "pfSense filterlog" --> S

&nbsp; W -- "UF: WinEventLog Security (4625)" --> S

```



---



\## Technical Validation



The experiment followed a structured validation sequence:



1\. \*\*Temporary Policy Adjustment\*\*

&nbsp;  - Enabled ATTACKNET → LAN RDP (TCP/3389) for controlled testing.

&nbsp;  - Confirmed pfSense logged PASS entries for the attack traffic.



2\. \*\*Attack Simulation\*\*

&nbsp;  - Generated failed RDP logon attempts from Kali.

&nbsp;  - Confirmed Windows logged Event ID 4625.

&nbsp;  - Verified ingestion of 4625 events into Splunk.



3\. \*\*Cross-Layer Correlation\*\*

&nbsp;  - Observed alignment between firewall PASS events and Windows 4625 failures.

&nbsp;  - Confirmed temporal relationship between network access and authentication attempts.



4\. \*\*Segmentation Restoration\*\*

&nbsp;  - Identified and removed unintended blanket allow rule on OPT1.

&nbsp;  - Observed pfSense logging BLOCK events for TCP/3389.

&nbsp;  - Verified no new 4625 failures occurred from the attacker source post-enforcement.



---



\## Field Normalization Note



pfSense firewall logs were ingested as generic syslog (`sourcetype=syslog`) without automatic field extraction. To enable structured analysis within Splunk, inline parsing was performed using SPL (`rex`, `split`, and `mvindex`) to extract key fields such as `action`, `src\_ip`, `dest\_ip`, and `dest\_port` from the filterlog CSV format.



This approach demonstrates the ability to normalize raw log data for detection engineering without relying on prebuilt technology add-ons, reflecting real-world SOC workflows where log formats must often be interpreted and structured manually.



---



\## MITRE ATT\&CK Mapping



\- \*\*T1110 — Brute Force\*\*  

&nbsp; Represents repeated authentication attempts against a remote service (RDP).



\- \*\*T1021.001 — Remote Services: Remote Desktop Protocol\*\*  

&nbsp; Represents the targeted access vector (RDP over TCP/3389).



Within this experiment:

\- \*\*T1021.001\*\* = Access vector  

\- \*\*T1110\*\* = Authentication abuse method  



---



\## Lessons Learned



\- Firewall rule hygiene is critical; a single unintended allow rule can undermine segmentation objectives.

\- Cross-layer telemetry provides stronger validation than single-source logging.

\- Temporary policy adjustments enable measurable security testing when carefully controlled.

\- Field normalization is often necessary when ingesting raw syslog data.

\- Prevention and detection should be validated together, not independently.



---



\## Professional Closeout



Phase 2 — Experiment 1 demonstrates that network segmentation can be validated, monitored, and proven using correlated telemetry across firewall and endpoint layers. By introducing controlled attack traffic, capturing multi-layer logs, correlating evidence in Splunk, and restoring enforcement, this experiment establishes a repeatable detection engineering workflow:



\*\*Introduce → Observe → Correlate → Enforce → Verify\*\*



This structured approach reflects practical defensive security methodology and forms the foundation for more advanced authentication abuse detection in subsequent phases.



