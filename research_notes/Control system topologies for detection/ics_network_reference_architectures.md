# ICS/OT Network Reference Architectures and Detection Sensor Placement

> **Verification status (updated 10 Nov 2026).** The first draft of these notes was written without web access. A second pass checked the main claims against live pages. Claims are now in one of three states:
> - **No mark:** checked in this session against the cited page (a primary page fetched directly, or stated consistently in search results from the named sources).
> - **(secondary):** confirmed only by search-result summaries of vendor/news pages, not by opening the primary document.
> - **(unverified):** still from background knowledge; the page could not be read (binary PDF, paywalled standard, 404) or does not contain the claim.
>
> The Inferences sections are the researcher's own design proposals, not sourced facts.

## Purdue Model (levels 0-5, level 3.5 DMZ): what sits where, traffic flow, attacks per level

### Takeaway
The Purdue model stacks the plant from physical process (L0) to enterprise IT (L4/5), with an industrial perimeter network (L3.5) between OT and IT. The project's flat model squeezes L0-L2, plus an attacker's "outside computer" that really belongs at L4/5 or the internet, onto one segment.

### Cited Findings
- NIST SP 800-82 Rev. 3, "Guide to Operational Technology (OT) Security," final dated 28 Sep 2023. Its abstract says it describes typical OT system topologies, common threats and vulnerabilities, and recommended countermeasures — [NIST CSRC](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
  - The landing page does not itself mention Purdue, DMZ, or unidirectional gateways. That Rev. 3 uses the Purdue model as an example segmented architecture and discusses DMZs and data diodes is (secondary) — [Secureframe summary](https://secureframe.com/blog/nist-800-82)
  - The same secondary source says NIST released an initial public draft of Rev. 4 on 21 Sep 2026 (unverified; check csrc.nist.gov before citing).
- Level contents, as described in Microsoft's Defender for IoT architecture guide (page dated April 2024, updated April 2026) — [Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/best-practices/understand-network-architecture):
  - **L0:** sensors, actuators, and devices in the basic process (driving a motor, measuring variables, setting an output).
  - **L1 (process control):** embedded controllers that talk to L0 devices: PLCs, RTUs, or a DCS in process plants.
  - **L2 (supervisory):** HMIs, alarm systems, process historian and batch management, control room workstations. These talk to the L1 PLCs/RTUs and run on standard computers and operating systems.
  - **L3 and L3.5 (site level and industrial perimeter network):** plant historian, production reporting and scheduling, patch launch server, file server, industrial domain/Active Directory, terminal server. Levels 0-3 are "considered critical to site operations."
  - **L4/5:** business and enterprise networks managed by IT.
- An industrial DMZ at L3.5 sits between the OT zone (L0-3) and the IT zone (L4-5), and traffic between them should pass through it (secondary) — [SentinelOne: What is the Purdue Model](https://www.sentinelone.com/cybersecurity-101/cybersecurity/what-is-the-purdue-model/)
- The CISA/ICS-CERT recommended practice "Improving ICS Cybersecurity with Defense-in-Depth Strategies" exists at the URL below (PDF metadata dated 2016). Its text could not be read in this session, so its specific recommendations (DMZ with separate firewalls, no direct corporate-to-control traffic) remain (unverified) — [CISA Defense-in-Depth 2016](https://www.cisa.gov/sites/default/files/recommended_practices/NCCIC_ICS-CERT_Defense_in_Depth_2016_S508C.pdf)
- MITRE ATT&CK for ICS technique IDs, as shown on the live matrix (Nov 2026) — [MITRE ATT&CK for ICS matrix](https://attack.mitre.org/matrices/ics/):

| Technique | ID | Tactic(s) |
|---|---|---|
| Adversary-in-the-Middle | T0830 | Collection |
| Manipulation of Control | T0831 | Impact |
| Manipulation of View | T0832 | Impact |
| Denial of Service | T0814 | Inhibit Response Function |
| Remote Services | T0886 | Initial Access; Lateral Movement |
| External Remote Services | T0822 | Initial Access |
| Internet Accessible Device | T0883 | Initial Access |
| Modify Controller Tasking | T0821 | Execution |
| Rogue Master | T0848 | Initial Access |
| Unauthorized Message: Command Message | T1692.001 | Evasion; Impair Process Control |
| Unauthorized Message: Reporting Message | T1692.002 | Evasion; Impair Process Control |

  - **Correction to the first draft:** the live matrix no longer lists "Unauthorized Command Message (T0855)" or "Spoof Reporting Message (T0856)" under those names. The closest entries are the two T1692 sub-techniques above. Older papers and tools still use T0855/T0856, so cite both if needed, and open the two technique pages to confirm the IDs before printing them on a slide.

### Inferences
- What attacks look like at each level, mapped to this project's attacks:
  - **L4/5 to L3:** phishing or remote-access compromise. Shows up as new external sessions and VPN/RDP logons. This matches the project's "command injection from outside computer," but in a real plant that computer has to cross L3.5 first.
  - **L3/L2:** HMI or engineering-workstation takeover (Ukraine 2015). Commands look *legitimate* because they come from an authorized host. "Writes from unknown host" will **not** fire.
  - **L2-L1 control network:** MITM, replay, and spoofed reporting. This is where the project's FDI, replay, and stealth spoof belong.
  - **L1 to L0:** compromised PLC logic (Stuxnet) or forged analog signals. No network evidence at all, so only physics-based or out-of-band checks can catch it.
  - **DoS** can sit at any level, but it hurts most on L1/L2, where polling is cyclic.
- Simulator idea: give each host a `level` attribute (L0 sensor A/B, L1 PLC, L2 HMI/engineering workstation, L3 historian, L3.5 jump host, L4 corporate PC, internet attacker). Give each attack an `entry_level` and a path. The website can draw the Purdue stack and animate the attack path.

### Gaps
- The NIST 800-82r3 PDF body was not read, so its exact treatment of Purdue levels, DMZ rules, and data diodes is not confirmed from the primary text.
- The CISA defense-in-depth PDF could not be parsed (binary).

## IEC 62443 Zones and Conduits: splitting a small plant; effect of firewalls and data diodes

### Takeaway
IEC 62443 groups assets with similar risk into **zones** and requires communication between zones to go through defined **conduits**. Conduits do not stop attacks that start inside a zone (MITM/replay on the field segment). They do turn cross-zone attacks (outside command injection, external DoS) into events that are **blocked or logged at a choke point**.

### Cited Findings
- IEC 62443-3-2 sets requirements for risk assessment in order to partition a control system into zones and conduits. A zone is a grouping of assets based on risk; communication between zones goes through conduits (secondary) — [IEC SyC Smart Energy: IEC 62443 background](https://syc-se.iec.ch/deliveries/cybersecurity-guidelines/security-standards-and-best-practices/iec-62443/)
- There are seven foundational requirements; "restricted data flow" is one of them (FR5). The security level of a zone or conduit is a vector with seven elements, one per foundational requirement. SL1 covers accidental violations and SL4 sophisticated intentional attacks (secondary) — [Trend Micro: system design and security level of IEC 62443](https://www.trendmicro.com/en_us/research/20/g/guidelines-related-to-security-in-smart-factories-part-2-system-design-and-security-level-of-iec62443.html)
  - Under FR5, the system requirements include SR 5.1 network segmentation and SR 5.2 zone boundary protection (secondary, same source).
- The standard text itself is paywalled and was not read. ISA's overview page was not opened (unverified) — [ISA: ISA/IEC 62443 Series](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)
- CISA's alert on the 2015 Ukraine attack recommends isolating ICS networks from untrusted networks, limiting remote access, and using "monitoring-only access enforced by data diodes" — [CISA IR-ALERT-H-16-056-01](https://www.cisa.gov/news-events/ics-alerts/ir-alert-h-16-056-01)
- Mandiant's TRITON write-up recommends "a unidirectional gateway rather than bidirectional network connections" for applications that depend on SIS data — [Mandiant/Google Cloud, 14 Dec 2017](https://cloud.google.com/blog/topics/threat-intelligence/attackers-deploy-new-ics-attack-framework-triton)
- Commercial unidirectional gateways (Waterfall, Owl Cyber Defense, Hirschmann) pass data through a data diode in one direction only. A monitoring sensor can sit outside the perimeter and receive mirrored traffic through the diode, or sit inside and send alerts out through it — [Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/best-practices/understand-network-architecture)

### Inferences
- **Small tank plant zoning (proposal):**
  - **Z0 Field/Safety zone:** sensor A, sensor B, level switches, pump/valve, flow meter. Sensor B and the switches are hard-wired, not on any network.
  - **Z1 Control zone:** PLC plus the field network. Sensor A sits here, e.g. Modbus/TCP.
  - **Z2 Supervisory zone:** HMI, engineering workstation, alarm server.
  - **Z3 Ops/DMZ:** historian, remote-access jump host.
  - **Z4 Enterprise/Internet.**
  - **Conduits:**
    - C1 (Z1-Z2) industrial firewall with a protocol allow-list (only HMI may write, only certain registers);
    - C2 (Z2-Z3) firewall;
    - C3 (Z3-Z4) firewall or data diode (outbound only).
- **Effect per attack type:**
  - *Command injection from outside:* a diode makes it physically impossible from Z4. With a firewall, it is blocked unless the attacker goes through an allowed path (VPN/jump host into Z2). The attacker then *looks like* the HMI, so "unknown host" detection fails and you need behavioral or setpoint-range checks.
  - *DoS flood from outside:* stopped at the conduit, and the conduit's own counters show it. A DoS from inside Z1 (a compromised device) is not stopped.
  - *Replay / FDI / MITM on sensor A:* need a foothold inside Z1 (or physical access to the cable). Conduits do not help. Detection must use physics (A vs B vs switches vs mass balance), watermarking, or authenticated protocols.
  - *Noisy replay / stealth spoof:* same as above. A diode does nothing for these.
- **Simulator idea:** model conduits as objects with `allow_rules` and `counters` (dropped packets, denied writes). An attack has to traverse conduits from its entry zone. The detector then gets per-conduit evidence: "denied write at C1 from Z2 host X" localizes the entry point.

### Gaps
- Exact SL1-SL4 wording and FR numbering were not checked against the standard text (paywalled). Current editions (3-2: 2020, 3-3: 2013 per a vendor table) are unconfirmed.

## Where OT NIDS sensors tap the network; level 1 vs level 2 visibility

### Takeaway
OT network detection is passive: sensors receive mirrored traffic from switch SPAN ports or network TAPs. Vendor guidance is to place them low, at L1/L2 near the access switches. A sensor placed high, near the enterprise firewall or in the DMZ, sees servers and workstations but misses PLC traffic and L0-L2 device detail. No network sensor sees hard-wired signals or changes inside a controller.

### Cited Findings
- Defender for IoT sensors "receive mirrored traffic, such as from switch mirror (SPAN) ports or network TAPs." The recommended monitoring points are the interfaces between a subnet's default gateway and the core/distribution switch, which capture traffic leaving the segment — [Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/best-practices/understand-network-architecture)
  - Unicast traffic that stays inside a segment does not cross the gateway. To see it, place sensors directly on the access switches (same source).
  - Monitor both directions of traffic; one-direction mirroring leaves gaps (same source).
  - Unusual traffic may need extra capture points such as RSPAN or network TAPs (same source).
- A sensor installed only in the outgoing DMZ misses much inventory data, including the types and versions of L0-L2 devices. A sensor too close to the enterprise firewall shows no L0/L1 devices (secondary, Microsoft documentation and tech community posts) — [Microsoft Tech Community](https://techcommunity.microsoft.com/t5/azure-defender-for-iot/designing-a-robust-defense-for-operational-technology-using/ba-p/2281869)
- Another vendor guide places probes at SPAN or TAP points on the firewalls, switches, or routers that separate Purdue zones (secondary) — [SenseOn docs](https://docs.senseon.io/en/latest/network_probe_purdue/)
- OT detection is "predominantly passive," and placement must also account for serial and fieldbus segments such as PROFIBUS and DeviceNet, which Ethernet mirroring does not cover (secondary) — [SC World explainer](https://www.scworld.com/tech-explainer/what-ot-detection-actually-reveals)
- ICSNPP is a set of ICS protocol parser plugins for Zeek, hosted by CISA on GitHub (copyright Battelle Energy Alliance, the INL operator). Full parsers include BACnet, BSAP, EtherCAT, EtherNet/IP and CIP, OPC UA Binary, S7comm, Profinet IO CM, and Synchrophasor. DNP3 and Modbus are extension scripts on top of Zeek's built-in analyzers — [cisagov/icsnpp](https://github.com/cisagov/icsnpp)
- Malcolm (also cisagov / Battelle Energy Alliance) is a traffic analysis suite for PCAP files, Zeek logs, and Suricata alerts, with Arkime and OpenSearch Dashboards. It takes uploaded PCAPs and live traffic passively captured by lightweight forwarders — [cisagov/Malcolm](https://github.com/cisagov/Malcolm)
- Network IDS cannot see changes made at the equipment or control layer, and cannot detect sensor compromise that happens below the network. Process-aware IDS checks the physical consistency of sensor data, in one design directly at field stations. A 2024 study reports that combining network traffic with process data improved recall (secondary; papers not opened) — [Real-world case studies for a process-aware IDS, 2025](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12174273/); [arXiv 2412.04902](https://arxiv.org/html/2412.04902v1)
- Zeek's built-in Modbus log records function codes, so reads and writes can be told apart (unverified; the docs URL tried returned 404).

### Inferences
- **SPAN vs TAP:** a mirror port shares the switch's resources and can drop packets under load, e.g. during a DoS flood; a TAP is a separate passive device per link (general networking knowledge, not sourced here). For the simulator, a `sensor_type="span"` could have a drop probability that grows with traffic, so the DoS flood partly blinds the sensor.
- **What a sensor at the L2 (supervisory) switch sees:**
  - HMI-PLC reads/writes, new hosts, remote-access sessions from Z3/Z4, and write commands with their values.
  - It **misses** a MITM between sensor A and the PLC if that traffic stays on a separate L1 field segment. This is the "unicast inside the segment" case from the Microsoft guidance.
- **What a sensor at the L1 field segment sees:**
  - Sensor A's reports as they leave the device, timing jitter (replay often breaks the cadence or transaction IDs), and ARP spoofing.
  - It **misses** enterprise/remote-access context.
- **Neither one sees** sensor B on hard-wired 4-20 mA or the level switches unless the PLC reports them, and neither sees tampering with PLC logic.
- **Simulator idea:** replace the single "detector co-located with controller" with 2-3 detectors:
  - (D1) field-segment tap;
  - (D2) supervisory/conduit sensor;
  - (D3) process-physics monitor reading the out-of-band hard-wired channel.
  - Fuse their alerts. Which detectors fire tells you where the attack came from. The process-aware IDS literature above supports combining network and process data.

### Gaps
- No Dragos, Nozomi, or Claroty placement whitepaper was retrieved; the vendor guidance here is Microsoft's and SenseOn's.
- The peer-reviewed papers were found by search only and not read. No paper specifically on optimal sensor placement per Purdue level was found.

## Out-of-band / independent monitoring: hard-wired sensors, SIS (IEC 61511 / ISA-84), and TRITON

### Takeaway
A Safety Instrumented System (SIS) is a separate protection layer with its own sensors, logic solver, and final elements. TRITON/TRISIS (2017) reprogrammed Triconex safety controllers from a network-reachable engineering workstation, which shows the independence has to be physical and network-level, not only on paper.

### Cited Findings
- TRITON facts from Mandiant's primary write-up, published 14 Dec 2017 — [Mandiant/Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/attackers-deploy-new-ics-attack-framework-triton):
  - Targeted Schneider Electric Triconex SIS controllers that "provided emergency shutdown capability for industrial processes" at a critical infrastructure organization. The write-up does not name the country or sector.
  - The attacker "gained remote access to an SIS engineering workstation" (Windows) and used TRITON, disguised as the legitimate `trilog.exe`, to talk to the controllers over the proprietary TriStation protocol.
  - It was noticed because some SIS controllers "entered a failed safe state, which automatically shutdown the industrial process." Application code between redundant processing units failed a validation check.
  - Recommendations: segregate safety networks from process control and IT networks; SIS engineering workstations "should not be dual-homed"; do not leave the Triconex physical key in PROGRAM mode; use a unidirectional gateway for applications that need SIS data; monitor ICS traffic for unexpected flows.
- That the victim was a Saudi petrochemical plant comes from later press reporting, not the Mandiant post (secondary) — [Infosec Institute](https://resources.infosecinstitute.com/triton-malware-hits-critical-infrastructure-saudi-arabia/)
- Schneider later said the framework used a zero-day in the Triconex controller and included a remote access trojan. A second victim of the same toolset was reported later (secondary) — [Dark Reading](https://www.darkreading.com/vulnerabilities-threats/schneider-electric-triton-trisis-attack-used-0-day-flaw-in-its-safety-controller-system-and-a-rat)
- Dragos's report is titled "TRISIS: Analyzing Safety System Targeting Malware" (page not opened) — [Dragos](https://dragos.com/?p=1399)
- IEC 61511-1:2016 (edition 2) added clause 8.2.4: a security risk assessment "shall be carried out" for the SIS and any device connected to it. Clause 11.2.12 requires the SIS design to provide resilience against the identified security risks. The standard points to ISA/IEC 62443 for detailed guidance (secondary) — [exida: How Secure Is Your SIS](https://www.exida.com/Blog/How-Secure-Is-Your-Safety-Instrumented-System-SIS); [IChemE Hazards 26 paper on IEC 61511 edition 2](https://www.icheme.org/media/11752/hazards-26-paper-15-iec-61511-functional-safety-in-the-process-industry-the-long-awaited-iec-61511-edition-2-and-what-it-means-for-the-process-industry.pdf)
- That IEC 61511 requires independence between the SIS and the basic process control system (BPCS) is standard industry understanding, but no source read in this session states the exact clause (unverified).
- CISA's Oldsmar advisory recommends "independent cyber-physical safety systems," such as limits on pump or reservoir size, so a compromised controller cannot push chemicals to dangerous levels — [CISA AA21-042A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-042a)

### Inferences
- In the project, **backup sensor B (hard-wired) plus the level switches already form an embryonic out-of-band/SIS layer**. To make it explicit:
  - Add an independent "SIS logic solver" that reads B and the HIGH-HIGH switch and trips the pump/closes the inlet valve on its own. Use a separate trip path that the attacker on the control network cannot write to.
  - Detection value: if the PLC says "level 40%" (spoofed A) while SIS B says 95% and the HH switch trips, that disagreement is the clearest attack/fault signature.
  - Show a "TRITON mode" scenario: the attacker also compromises the SIS engineering link. This is only possible if the SIS workstation is dual-homed onto the control network, which shows judges why SIS isolation matters. A "key switch in PROGRAM mode" toggle would be a faithful detail.
  - The CISA pump-size-limit idea maps directly: cap the pump's maximum fill rate physically so no command can overfill faster than the SIS can react.
- Fault vs. attack heuristic:
  - A single faulty sensor makes **one** channel disagree with physics.
  - An attack on the network channel makes the **network** channel disagree while **all** out-of-band channels agree with each other and with mass balance (inflow − outflow = A·dh/dt).

### Gaps
- IEC 61511 text is paywalled; clause wording is from secondary sources.

## How zoning lets a detector localize attack entry; which attacks are visible/invisible at each sensor

### Takeaway
With several sensors placed per zone, each attack leaves a distinct **fingerprint**: which sensors alert and which stay silent. That fingerprint shows the entry point (enterprise/remote vs. supervisory vs. field) and separates network attacks from physical faults.

### Cited Findings
- ATT&CK for ICS separates Initial Access techniques (External Remote Services T0822, Internet Accessible Device T0883, Remote Services T0886) from in-network ones (Adversary-in-the-Middle T0830, Unauthorized Message T1692.x). This supports modeling attacks by entry point and path — [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- Sensor position determines what is visible: a high-placed sensor misses L0/L1 devices, and in-segment unicast traffic needs a sensor on the access switch — [Microsoft Learn](https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/best-practices/understand-network-architecture)

### Inferences
Proposed visibility matrix for the simulator. This is the researcher's design, not a published result. Sensors:
- **D_conduit:** firewall/IDS at Z3/Z4-Z2.
- **D_sup:** span on the supervisory switch, Z2.
- **D_field:** tap on sensor A's segment, Z1.
- **D_phys:** physics plus out-of-band B/switches/power/flow.
- **Watermark:** controller probe.

| Attack (entry) | D_conduit | D_sup | D_field | D_phys | Watermark |
|---|---|---|---|---|---|
| Command injection from internet host (Z4) | **Yes**: new external flow / denied | Yes if it got through: write from unexpected source | Maybe (PLC actuates) | Yes: actuator change vs. demand | No |
| Command injection via hijacked HMI/remote access (Ukraine 2015-style, Z2) | Remote-session log only | Weak: legitimate host; needs setpoint-range rules | No | Yes if the setpoint is unsafe | No |
| DoS flood from Z4 | **Yes**: blocked at conduit | No (if blocked) | No | No | No |
| DoS from inside Z1 | No | Maybe | **Yes**: volume, latency, missed polls | Indirect: stale A | Probe response delayed |
| FDI on sensor A (Z1) | No | Values look plausible | Yes if a value differs from what PLC got (MITM) or rate is unusual | **Yes**: A vs B / switches / mass balance | Yes |
| Replay (Z1) | No | No | Yes: duplicated transaction IDs, timing | Yes over time (A stuck to old pattern) | **Yes**: probe missing from replayed data |
| Noisy replay (Z1) | No | No | Weak | Yes | **Yes** |
| Stealth spoof/MITM (Z1) | No | No | Yes: ARP anomaly, duplicate MAC | Yes slowly (residual drift) | **Yes** |
| Physical sensor fault (no network) | No | No | No | **Yes**: only A disagrees, network clean | Depends on model |

- Localization rule: the **highest-zone sensor that fires is the entry level**. If only D_field and D_phys fire, the attacker is already inside Z1. If D_conduit fires, the entry was external. If only D_phys fires and all network sensors are clean, suspect a **fault** (or an L0/PLC-logic compromise like Stuxnet; flag that as ambiguous).
- Website idea: a toggle between a "flat" and a "zoned" topology, with the same attack run on both. In flat mode the single detector sees everything but can't localize. In zoned mode the outside attacks are blocked/seen at the conduit, and in-zone attacks still need physics plus the watermark.

### Gaps
- No published dataset or paper was retrieved to back this exact matrix.

## Real incidents illustrating that topology matters (short facts)

### Takeaway
Each incident exploited a topology weakness: an air gap crossed by removable media and a replayed view (Stuxnet), stolen credentials and remote access into the control system (Ukraine 2015), malware speaking grid protocols from inside the network (Ukraine 2016), remote desktop access to a SCADA PC (Oldsmar), and IT ransomware halting OT operations (Colonial).

### Cited Findings
- **Stuxnet (found 2010):**
  - Attacked two Siemens controller types at Natanz. The S7-315 code manipulated up to 186 centrifuge drives, cycling rotor speeds. The S7-417 code attacked the cascade protection system's valves and pressure sensors (secondary, summarizing Langner) — [Langner, "To Kill a Centrifuge" (2013)](https://www.langner.com/wp-content/uploads/2017/03/to-kill-a-centrifuge.pdf); [Langner's Stuxnet page](https://www.langner.com/stuxnet)
  - The 417 attack recorded 21 seconds of normal sensor values and replayed them in a loop during the attack, so operators saw normal readings (secondary, Langner and Symantec summaries) — [Dark Reading on Langner's analysis](https://www.darkreading.com/cyberattacks-data-breaches/stuxnet-s-earlier-version-much-more-powerful-and-dangerous-new-analysis-finds)
  - Natanz was air-gapped. Entry by an infected USB drive, using a Windows shortcut (LNK) flaw, is the leading theory rather than a confirmed fact (secondary) — [CSO Online: What is Stuxnet](https://www.csoonline.com/article/3218104/malware/what-is-stuxnet-who-created-it-and-how-does-it-work.html)
- **Ukraine, 23 Dec 2015** — [CISA IR-ALERT-H-16-056-01](https://www.cisa.gov/news-events/ics-alerts/ir-alert-h-16-056-01):
  - Three regional distribution companies were hit within 30 minutes of each other; about 225,000 customers lost power.
  - Attackers opened breakers remotely using existing remote administration tools or remote ICS client software over VPN, apparently with legitimate credentials obtained beforehand.
  - KillDisk wiped systems at the end. Firmware on serial-to-Ethernet devices at substations was corrupted. Server UPS units were scheduled to disconnect.
  - BlackEnergy was found on all three networks, reportedly delivered by spear-phishing, but **CISA says its role in the attack is unconfirmed**. (The first draft stated it as the access method; corrected.)
  - The attackers also generated thousands of calls to the companies' phone lines (secondary; from the E-ISAC/SANS report of 18 Mar 2016, PDF not read) — [E-ISAC/SANS Defense Use Case](https://nsarchive.gwu.edu/sites/default/files/documents/3891751/SANS-and-Electricity-Information-Sharing-and.pdf)
  - Outage duration ("several hours") is (unverified); the CISA alert gives none.
- **Ukraine, 17 Dec 2016 (Industroyer/CRASHOVERRIDE):**
  - The malware had payloads for IEC 60870-5-101, IEC 60870-5-104, IEC 61850, and OPC DA, so it could command substation switches and breakers directly (secondary) — [ESET Industroyer whitepaper (2017)](https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf)
  - Dragos assessed with high confidence that it was used to de-energize a Kyiv transmission substation on 17 Dec 2016. ESET was more cautious and did not confirm that link (secondary) — [Dragos: CRASHOVERRIDE](https://dragos.com/?p=1401); [report PDF copy](https://nsarchive.gwu.edu/sites/default/files/documents/3869008/Dragos-CRASHOVERRIDE-Analyzing-the-Threat-to.pdf)
  - The outage lasting about one hour is from lower-quality secondary notes (unverified).
- **Oldsmar, Florida water plant, 5 Feb 2021:**
  - CISA's advisory (which does not name Oldsmar) says unidentified actors accessed a US water facility's SCADA system on 5 Feb 2021 and raised sodium hydroxide dosing. Staff noticed and corrected it before the SCADA software flagged the change — [CISA AA21-042A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-042a)
  - Access was "likely" through desktop sharing software such as TeamViewer, but CISA says this "cannot be confirmed." Poor password security and outdated Windows 7 are cited as likely weaknesses (same source).
  - The advisory gives no quantities. The sheriff said at the time the lye level was raised by a factor of 100 (secondary). The 100 ppm to 11,100 ppm figures in the first draft are (unverified).
  - **Disputed:** in March 2023 former city manager Al Braithwaite called it a "non-event" caused by user error, saying FBI officials told him an employee likely caused it by accident. The FBI said only that it could not confirm a targeted cyber intrusion (secondary) — [Industrial Cyber](https://industrialcyber.co/news/oldsmar-water-treatment-plant-incident-allegedly-caused-by-human-error-not-remote-access-cybersecurity-breach/); [ABC Action News](https://www.abcactionnews.com/news/local-news/i-team-investigates/fbi-and-former-city-manager-say-oldsmar-cyberattack-never-happened)
- **Colonial Pipeline, 7 May 2021:**
  - Ransomware attack on 7 May 2021 led to fuel lines and stockpiling along the US East Coast; TSA issued pipeline Security Directives afterward — [CISA, 2023 retrospective](https://www.cisa.gov/news-events/news/attack-colonial-pipeline-what-weve-learned-what-weve-done-over-past-two-years)
  - Attackers entered through a VPN account that was no longer in regular use and had no multi-factor authentication (secondary, Bloomberg/Mandiant via trade press) — [BankInfoSecurity](https://www.bankinfosecurity.com/hackers-used-compromised-password-to-get-into-colonial-pipeline-a-16819)
  - Colonial paid 75 bitcoin (about USD 4.4M; one outlet says 4.3M) to DarkSide. The DOJ recovered 63.7 bitcoin, worth about USD 2.3M by then (secondary) — [The Record](https://therecord.media/doj-officials-say-they-recovered-most-of-the-colonial-ransomware-payment)
  - That the ransomware hit IT only and the pipeline (~5,500 miles) was shut down as a precaution is widely reported but was not confirmed by a source read in this session (unverified).

### Inferences
- How the incidents map onto the simulator:
  - Stuxnet maps onto "replay + stealth spoof." It shows why an out-of-band physical check and watermarking matter: the operator view was a 21-second loop.
  - Ukraine 2015 maps onto "command injection from an authorized HMI." Here the "unknown host" counter fails, so you need setpoint-limit and rate rules. Its serial-to-Ethernet firmware attack also shows attackers target the L1 field gateways.
  - Oldsmar is the best "fault or attack?" story for this project: two years later it is still unclear whether it was an intruder or an operator mistake. Present it that way, not as a confirmed hack.
  - Colonial suits a Downstream Oil & Gas audience (Brunei), and argues for an explicit L3.5 boundary in the model.
  - TRITON (previous section) is the petrochemical-safety example most relevant to the Downstream O&G safety track.

### Gaps
- Primary PDFs (Langner, ESET, E-ISAC/SANS, Dragos) were not opened; their facts are from search summaries.
- Ukraine 2015 and 2016 outage durations, the Oldsmar ppm values, and Colonial's IT-only/precautionary-shutdown detail still need a primary source.
