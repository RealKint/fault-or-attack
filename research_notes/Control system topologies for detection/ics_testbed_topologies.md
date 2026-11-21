# ICS Testbed and Benchmark Process Topologies for Fault/Attack Detection

> **How to read the evidence tags.** Web access failed at first and was restored part-way through. Each finding carries one tag:
> - **[F]**: the cited page was fetched and read this session.
> - **[S]**: taken from a search-result summary this session. The cited page itself was not opened, so wording and numbers are second-hand.
> - **[V]**: verified in an earlier session of this project (copied from `research_notes/Fault versus attack detection methods/*.md`).
> - **[K]**: researcher's prior knowledge of the primary paper. **Not verified this session.** The link is the canonical paper. Check before quoting.
>
> Several primary PDFs (Mathur & Tippenhauer 2016, Morris & Gao 2014, Taormina et al. 2018) could not be read (binary PDF, paywall or bot block), so some details rest on secondary sources.

---

## Q1. SWaT (iTrust, SUTD): stages, PLCs, network, sensors/actuators, attacks, cross-stage invariants

### Takeaway
SWaT is a 6-stage water-treatment plant. Each stage has its own PLC plus a backup PLC, an Ethernet ring to its field devices and a separate star network between PLCs. The 2015 dataset has 51 tags and 36 documented attacks, classified by how many stages and points they touch. The detection idea most useful to "Fault or Attack" is the design-derived invariant: a per-tank mass balance plus state rules such as "valve open ⇒ flow non-zero", some of which use data from neighbouring stages.

### Cited Findings
- [F] SWaT is a six-stage water treatment plant with one PLC per stage plus one backup PLC per stage, distributed control and an HMI. PLC-to-sensor/actuator traffic uses an Ethernet ring. PLC-to-PLC traffic uses a separate Ethernet star. Protocols are EtherNet/IP and CIP. Attacks are single-stage or multi-stage and single-point or multi-point, with the attacker either on the plant network or physically on site. — [Conti et al., ICS testbed/dataset survey, arXiv 2102.05631](https://ar5iv.arxiv.org/html/2102.05631)
- [F] SWaT dataset A1 (2015): about 11 days, about 950K entries, network and physical data, 5.76% of entries under attack. — [arXiv 2102.05631](https://ar5iv.arxiv.org/html/2102.05631)
- [V] SWaT.A1 (Dec 2015): 7 days normal plus 4 days with attacks, 51 sensors/actuators. iTrust's page says 41 attacks were launched. Later releases run to A9 (Dec 2023). There are no labelled physical faults. — [iTrust SWaT page](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/swat/)
- [S] Papers using the dataset count **36 attacks** over the 4 attack days, split as SSSP 26, SSMP 4, MSSP 2, MSMP 4 (single/multi stage, single/multi point). This conflicts with iTrust's "41". — [Kravchik & Shabtai, arXiv 1806.08110](https://arxiv.org/pdf/1806.08110); contradicted by [iTrust SWaT page](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/swat/)
- [S] Stage 1: LIT101 measures the raw-water tank level, motorised valve MV101 controls the inflow, and pump P101 sends water on to stage 2. Each controller is paired with a remote I/O device. One source counts 36 sensors in the plant. — [arXiv 1806.08110](https://arxiv.org/pdf/1806.08110); [Code attestation for PLCs, arXiv 2106.07851](https://arxiv.org/pdf/2106.07851)
- [K] Remaining stage detail, not verified: P2 chemical dosing (dosing pumps P201–P206, analysers AIT201–203), P3 ultrafiltration (feed tank T301 with LIT301, DPIT301), P4 dechlorination (tank T401 with LIT401, UV unit), P5 reverse osmosis, P6 permeate storage and backwash. The 51 tags are usually given as 25 sensors and 26 actuators. Flow is about 5 US gal/min. PLCs are Allen-Bradley. — [Mathur & Tippenhauer, CySWater 2016](https://doi.org/10.1109/CySWater.2016.7469060); [Goh et al., CRITIS 2016](https://doi.org/10.1007/978-3-319-71368-7_8)
- [S] Adepu & Mathur's distributed detection uses physical invariants derived for each stage from the plant design. An invariant must hold either throughout operation or when the plant is in a given state. — [Adepu & Mathur, AsiaCCS 2016 (CPS-VO record)](https://archive.cps-vo.org/node/35339)
- [S] State-dependent (SD) invariant example: when MV101 is open, FIT101 must give a non-zero reading. SD invariants may include conditions from several stages, which is what makes detection distributed. State-agnostic (SA) invariants are one per tank: the level change equals α × (inflow − outflow), with α set by the tank dimensions. In the S3 hackfests the detection code ran inside the PLCs and was spread across controllers. — [Hackfest assessment paper, arXiv 1809.04786](https://arxiv.org/pdf/1809.04786)
- [V] Data-driven invariant mining (Feng et al., NDSS 2019) finds many more rules than manual design and claims zero false positives. — [NDSS page](https://ndss-symposium.org/ndss-paper/a-systematic-framework-to-generate-invariants-for-anomaly-detection-in-industrial-control-systems)
- [V] SWaT labels samples as attack from launch, not from when the physical effect begins. — [arXiv 2102.05631](https://arxiv.org/html/2102.05631)

### Inferences
- **Borrow from SWaT:** a second tank in series (T1 → pump → T2) with **its own controller**. A false LIT1 reading must then also stay consistent with T2's level change and the transfer flow. That pushes the attacker from single-point (26 of SWaT's 36 attacks) to multi-stage multi-point, the rarest and hardest class.
- Fault vs attack: a real leak in T1 breaks only T1's balance. A spoofed LIT1 breaks T1's balance and contradicts T2's inflow history. A real pump failure shows in both tanks (T1 stops draining, T2 stops filling). A spoofed pump status leaves T2 rising.
- The project's existing mass-balance and actuator-feedback checks are SWaT's SA and SD invariants for one tank. The gap is cross-stage SD invariants, which need a second stage.
- The ring (Level 0) vs star (Level 1) split maps onto the project's hard-wired sensor B: B stands for data that never crosses the PLC-to-PLC/SCADA network.

### Gaps
- 36 vs 41 attacks is unresolved. The dataset papers use 36.
- The 25/26 sensor/actuator split, tank tag names beyond stage 1 and PLC vendor are [K] only. One secondary source says "36 sensors", which does not match 25.
- The exact SA invariant equation and thresholds for LIT101 were not seen in a primary source.

---

## Q2. WADI and BATADAL / C-Town: topology and how attacks hide across a network

### Takeaway
WADI is a real distribution testbed with raw-water tanks, elevated reservoirs and six consumer tanks, 123 tags and 15 attacks over 2 days. BATADAL's C-Town is a simulated town network with 7 tanks, 11 pumps and 9 PLCs, 43 SCADA variables and 14 attacks. Concealment works by replaying old readings, but measured results show replay only hides an attack when almost every sensor is replayed. Partial replay makes detection easier, which is the argument for many cross-checked signals.

### Cited Findings
- [S] WADI dataset: 16 days of continuous operation, 14 normal and 2 with attack scenarios, all 123 sensors and actuators, 15 attacks. The network has three control processes (primary grid, secondary grid, return-water grid), each with its own set of PLCs. — [iTrust WaDi page](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/wadi/)
- [F] WADI physical layout: "two elevated reservoir tanks, six consumer tanks, two raw water tanks, and a return tank", plus chemical dosing, booster pumps, valves and analysers. Stages are P1 (primary supply and analysis), P2 (elevated reservoir with domestic grid and leak detection) and P3 (return). It is controlled by 3 PLCs over 103 network sensors. — [Erba et al., constrained concealment attacks, arXiv 1907.07487](https://ar5iv.labs.arxiv.org/html/1907.07487)
- [F] The survey instead describes WADI as five stages with three PLCs and two RTUs, about 10 US gal/min, Modbus/TCP at Level 0 and RTUs on HSPA/GPRS. It is physically linked to SWaT for cascade studies. About 950K entries, 1.04% under attack. — [arXiv 2102.05631](https://ar5iv.arxiv.org/html/2102.05631); stage count differs from [arXiv 1907.07487](https://ar5iv.labs.arxiv.org/html/1907.07487)
- [S] Sources split the 123 tags differently (88 sensors/35 actuators in one paper, 67 sensors/60 actuators in another). — search summary of [arXiv 2109.11428](https://arxiv.org/pdf/2109.11428) and related papers
- [V] WADI consumer tanks each have a modulating valve, flow meter and level switch. Watermarking the valve with random 25–45% openings and a K-S test detected replay at 100% TPR. — [Ahmed et al., J. Process Control 2022](https://strathprints.strath.ac.uk/81324/1/Ahmed_etal_JPC_2022_A_practical_physical_watermarking_approach_to_detect_replay_attacks.pdf)
- [S] BATADAL (2017): C-Town is a real-world, medium-sized network run by PLCs and SCADA. Remote sensors and actuators connect to **nine PLCs** that control the tanks, pumps and valves. Seven teams took part, using data analysis, model-based detection and rule checking. Scoring used time-to-detection and classification accuracy. — [Taormina et al. 2018, summary page](https://sdg.haifa.ac.il/?p=5432); [ASCE proceedings](https://ascelibrary.com/doi/10.1061/9780784480595.010)
- [S] C-Town network file: 388 junctions, 444 pipes, 1 reservoir, 7 tanks, 11 pumps, 4 valves. It was created for the 2011 Battle of the Water Calibration Networks and reused for BATADAL. — [WaterBenchmarkHub C-Town](https://waterfutures.github.io/WaterBenchmarkHub/benchmarks/network-CTown.html)
- [F] BATADAL data: 43 sensor variables, made up of 7 tank levels, 12 pressures (one actuated valve and all pumping stations) and 24 flow and status variables. 14 attacks, 7 in each of the two attack datasets. Generated with epanetCPA. — [arXiv 1907.07487](https://ar5iv.labs.arxiv.org/html/1907.07487)
- [F] BATADAL files: one year of normal training data, about six months of partially labelled data, and a test set of about three months (the survey says four). Attacks include malicious actuator activation, actuator setting changes, replay and man-in-the-middle. A newer version with unconcealed readings exists. — [WaterBenchmarkHub BATADAL](https://waterfutures.github.io/WaterBenchmarkHub/benchmarks/BATADAL.html); [arXiv 2102.05631](https://ar5iv.arxiv.org/html/2102.05631)
- [F] Sampling interval conflict: Erba et al. say BATADAL is sampled every 15 minutes. The project's earlier note records hourly readings. — [arXiv 1907.07487](https://ar5iv.labs.arxiv.org/html/1907.07487); contradicted by [WaterBenchmarkHub (earlier session)](https://waterfutures.github.io/WaterBenchmarkHub/benchmarks/BATADAL.html)
- [F] How concealment performs against a reconstruction-based detector:
  - Replaying **all** sensors cut recall from 0.60 to 0 on BATADAL and from 0.68 to 0.07 on WADI.
  - Replaying fewer than about 95% of features **raised** recall, because the mix of old and live readings created contextual anomalies. Replay hid attacks only when at least 40 of 43 sensors were controlled.
  - A white-box iterative attack cut recall to 0.14 (BATADAL) and 0.07 (WADI). A black-box learned attack cut it to 0.14 and 0.31.
  
  — [arXiv 1907.07487](https://ar5iv.labs.arxiv.org/html/1907.07487)

### Inferences
- **Borrow from C-Town:** let the pump controller act on a level reported by a *different* controller over the network. This is the PLC-to-PLC link pattern. It adds an attack path that never touches the actuated tank's own sensor, and a new invariant: pump ON ⇒ the remote tank rises at the expected rate.
- The 40-of-43 result is the strongest quantitative argument for adding signals. With few signals, as in the single tank, an attacker can replay everything and stay consistent. Each extra independent signal (sensor B, a second tank level, a transfer flow, a pressure) raises the fraction of the plant the attacker must control.
- Hard-wired sensor B is the single-tank version of "a sensor the attacker cannot replay". The WADI figures suggest even one such signal should expose a replay as a contextual anomaly.
- WADI's valve watermarking maps directly onto the project's PID-valve option.

### Gaps
- Taormina et al. 2018 could not be read. Which PLC controls which tank/pump, and which attacks used concealment, are not verified.
- C-Town valve and pipe counts for the BATADAL variant may differ from the 2011 file (my unverified recollection was 429 pipes and 5 valves).
- WADI stage count (3 vs 5) and PLC/RTU count differ between sources.

---

## Q3. HAI (ETRI/NSR): four processes, coupling, controllers, 22.04 points

### Takeaway
HAI links a boiler (Emerson Ovation), a turbine rotor kit (GE Mark VIe) and a water-treatment loop (Siemens S7-300) through a dSPACE hardware-in-the-loop simulator. HAI 22.04 has 86 points per second, 6 normal files and 4 attack files. **The repo table gives 58 attacks for 22.04, not the 34 recorded in the project's earlier note.**

### Cited Findings
- [F] The four processes:
  - **P1 Boiler:** water-to-water heat transfer at low pressure and moderate temperature. Emerson Ovation DCS.
  - **P2 Turbine:** a rotor kit that simulates a rotating machine. GE Mark VIe DCS.
  - **P3 Water treatment:** pumps water to an upper reservoir and releases it to a lower reservoir. Siemens S7-300 PLC.
  - **P4 HIL simulation:** dSPACE SCALEXIO, connected to the real processes through a Siemens S7-1500 PLC and ET200 remote I/O.
  
  — [HAI repo README](https://github.com/icsdataset/hai)
- [F] Coupling: boiler and turbine are synchronised to the rotating speed of a virtual steam-turbine generation model. The water-treatment pump and valve are driven by a pumped-storage hydropower model. The README says the HIL simulator makes "the variables … highly coupled and correlated". An OPC-UA gateway collects data from the three vendors' devices. — [HAI repo README](https://github.com/icsdataset/hai)
- [F] Data points per second by version: 59 (HAI 20.07), 78 (21.03), 86 (22.04), 86 (HAI 23.05), 225 (HAIEnd 23.05). The 23.05 pair shares one table row, so the 86/225 assignment is read from formatting. — [HAI repo README](https://github.com/icsdataset/hai)
- [F] HAI 22.04 file table: six training files (train1–train6) with values 26, 56, 35, 24, 66 and 72 that total 279, and 534.4 MB. Four test files (test1–test4) of 24, 23, 17.3 and 36 hours (100.3 h) with values 7, 17, 10 and 24 that total 58, and 195.6 MB. I read 279 as training hours and 58 as the attack count. The fetch tool mislabelled these columns, so confirm the headers in the README. — [HAI repo README](https://github.com/icsdataset/hai)
- [V] The earlier project note recorded 22.04 as 3 training and 3 test files with 7 + 17 + 10 = 34 attacks, and treated "6 files, 279 h, 58 attacks" as an unofficial mirror's figure. The official table now seen matches the mirror. The 34 figure is the first three test files only. — project note `datasets_and_ml.md`; [HAI repo](https://github.com/icsdataset/hai)
- [F] Other versions: HAI 20.07 lists 38 attacks, HAI 21.03 lists 50, HAI/HAIEnd 23.05 lists 52. — [HAI repo README](https://github.com/icsdataset/hai)
- [V] HAI 1.0 was released in Feb 2020. Per-process attack labels were dropped from 22.04 onward. Sampling is 1 Hz. — [Shin et al., USENIX CSET 2020](https://www.usenix.org/conference/cset20/presentation/shin); [HAI repo](https://github.com/icsdataset/hai)
- [K] Tag names, not verified this session: P1_LIT01 (return-water tank level), P1_LCV01D/Z (level valve demand and position), P1_FCV01–03 D/Z, P1_FT01–03, P1_PIT01/02, P1_PP01/02; P3_LIT01, P3_FIT01, P3_LCV01D, P3_LCP01D, P3_LH/LL switches; P4_ST_* (steam turbine) and P4_HT_* (hydro turbine). — [HAI repo technical manual](https://github.com/icsdataset/hai)

### Inferences
- The project should restate its HAI 22.04 attack count as 58 across four test files, or say explicitly that it used test1–test3 only.
- HAI's demand/position pairs (…D vs …Z) are the actuator-feedback check the project already uses. Apply it to every actuator.
- HAI's distinctive feature is **coupling through setpoints, not through water**. A change in the HIL demand signal moves P1, P2 and P3 together with no physical fault. "Several loops moved together with no physical cause" is a candidate attack sign that a single tank cannot show.
- P3 (upper and lower reservoir, pump, valve, level switches) is closer to the project's tank than the P1 boiler loop and is a natural second validation loop.

### Gaps
- The exact P4-to-P1/P2/P3 signal paths and the 22.04 tag list were not re-read from the technical manual.
- No evidence of labelled physical faults in HAI was found, now or in the earlier session.

---

## Q4. EPIC (electric power) and the Tennessee Eastman process

### Takeaway
EPIC is iTrust's 72 kVA power testbed with four stages, and it physically powers SWaT and WADI. TEP is a simulated five-unit chemical plant with 41 measurements, 12 manipulated variables and 20 disturbances. TEP is the one benchmark with published work on telling disturbances from intrusions, with only partial success.

### Cited Findings
- [F] EPIC is a 72 kVA testbed with four stages: Generation, Transmission, Micro-grid and Smart Home. Each stage is controlled by PLCs connected to a master PLC through switches and then to a SCADA gateway. It has two motor-driven generators, photovoltaic panels and a battery. It uses IEC 61850 over TCP/IP. It supplies power to SWaT and WADI, which allows cascade studies. Its dataset is about 4 hours. Attacks studied include false data injection, malware and power-supply interruption. — [arXiv 2102.05631](https://ar5iv.arxiv.org/html/2102.05631)
- [S] TEP has five main units (reactor, condenser, vapour–liquid separator, recycle compressor, product stripper), 41 measured variables (XMEAS), 12 manipulated variables (XMV) and 20 process disturbances (IDV). — [Filonov et al., arXiv 1709.02232](https://ar5iv.arxiv.org/html/1709.02232)
- [S] TEP attack sets: Filonov et al. (2017) attack measurements, manipulated variables and setpoints, and published the data. Other work attacks the purge valve XMV(6), the cooling-water valve XMV(10) and the agitator XMV(12), aiming to push reactor pressure past the 3000 kPa safety limit. — [arXiv 1709.02232](https://ar5iv.arxiv.org/html/1709.02232); [EPASAD, arXiv 2204.04154](https://arxiv.org/pdf/2204.04154); [arXiv 1804.11022](https://arxiv.org/pdf/1804.11022)
- [F] Iturbe et al. (DSN-W 2016) extend multivariate statistical process control to monitor both process-level and controller-level data on TEP. It separates disturbances from intrusions "to a certain extent", and the authors suggest adding other data sources. — [arXiv 1706.01679](https://arxiv.org/abs/1706.01679)
- [V] TEP fault sets: DTU (28 faults × 6 modes × 500 runs) and Rieth (20 faults). Faults and attacks come from separate simulator runs. — [DTU data](https://data.dtu.dk/articles/dataset/Tennessee_Eastman_Reference_Data_for_Fault-Detection_and_Decision_Support_Systems/13385936)
- [F] TEP-based testbeds include GRFICS (OpenPLC, Modbus; attacks include command injection, false data injection and PLC reprogramming) and a NIST testbed. — [arXiv 2102.05631](https://ar5iv.arxiv.org/html/2102.05631)

### Inferences
- **Borrow from TEP:** Iturbe's idea of watching controller-level data (what the controller commanded) alongside process-level data (what happened) is the same split the project uses. Their "to a certain extent" result supports the project's choice to add network counters and a second sensor instead of relying on process data alone.
- TEP's recycle loop means a real fault spreads through many measurements in a physically consistent pattern. A spoofed sensor shows as one variable disagreeing with the rest. The project can use the same test: count how many linked signals moved.
- EPIC adds one idea: a shared upstream dependency. Power loss in the project could be modelled as a cascade from a separate monitored supply, so it is seen on an independent channel.

### Gaps
- Downs & Vogel 1993 was not read directly. TEP counts come from secondary sources that agree.
- EPIC PLC/IED vendors and dataset contents were not verified.

---

## Q5. Gas pipeline / water storage tank testbeds (Morris et al., Mississippi State)

### Takeaway
Morris & Gao's water storage tank is nearly the project's plant: a roughly 2-litre tank with on/off control between high and low setpoints, on Modbus. The gas pipeline is the oil-and-gas analogue: compressor, pressure meter and solenoid relief valve under PID. The datasets are network-traffic captures with 28 attacks, and the authors and later surveys warn they are flawed for ML.

### Cited Findings
- [S] The paper describes four datasets with network traffic, process-control and process-measurement features from **28 attacks** against **two laboratory-scale** control systems that use Modbus. — [Morris & Gao, ICCIP 2014 (IFIP)](https://dl.ifip.org/IFIP-AICT-441/hal-01386754)
- [S] Gas pipeline: a small airtight pipeline connected to a compressor, a pressure meter and a solenoid-controlled relief valve. It holds air pressure with a PID scheme. Water storage tank: holds about two litres and uses on/off control between high and low setpoints. — [Morris & Gao 2014](https://dl.ifip.org/IFIP-AICT-441/hal-01386754)
- [F] Dataset details from the survey:
  - Gas pipeline (Dataset 2): Modbus/RTU, about 397K samples, 0.97% abnormal, seven attack types, no timestamps. Burst and setpoint injection were the hardest to detect.
  - Gas pipeline and water tank (Dataset 3): captured with a bump-in-the-wire device. Attack families are reconnaissance, response injection, command injection and DoS. About 27% of data is under attack. The water tank set has 230K entries in ARFF format.
  - New gas pipeline (Dataset 4): 35 documented attacks covering 21.86% of the capture, about 270K entries.
  
  — [arXiv 2102.05631](https://ar5iv.arxiv.org/html/2102.05631)
- [V] The authors warn of unintended patterns that let ML models cheat. The 2015 new gas pipeline set adds randomness to fix this. — [UAH ICS datasets page](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets)
- [S] A 2022 survey calls the gas pipeline and water tank datasets flawed for ML research, as the authors acknowledge. — [arXiv 2202.11917](https://arxiv.org/pdf/2202.11917)
- [K] The seven attack classes, not verified this session: NMRI (naive malicious response injection), CMRI (complex malicious response injection), MSCI (malicious state command injection), MPCI (malicious parameter command injection), MFCI (malicious function code injection), DoS and reconnaissance. The water tank also has HH/LL alarm setpoints. — [Morris & Gao 2014](https://doi.org/10.1007/978-3-662-45355-1_5)

### Inferences
- The project's attacks already cover response injection (FDI, stealth spoof, replay), command injection and DoS. Two Morris families are missing and cheap to add:
  - **Parameter/setpoint injection**: change the 40/60% hysteresis band or the PID gains. The plant then behaves consistently around the wrong band, so physics checks pass. Only a configuration-integrity check catches it. The survey notes setpoint injection was among the hardest to detect.
  - **Reconnaissance / unusual function codes**: visible only in network counters.
- The label-leakage warning applies to the project's own simulated data. Scenarios should randomise spoof values, timing and magnitudes so faults and attacks are not trivially separable.
- For an oil-and-gas angle, the gas pipeline suggests adding a pressure variable and a relief valve as a second, faster loop.

### Gaps
- The primary paper was blocked (bot protection), so the exact attack-class names, the water tank's alarm setpoints and feature lists are unverified.
- The survey says "Mississippi State University" and does not name Morris. Attribution comes from the UAH page.

---

## Q6. Coupled-tank benchmarks (quadruple-tank, three-tank DTS200): why multiple tanks help

### Takeaway
On the quadruple-tank process, Teixeira et al. ran real attacks: a zero-dynamics attack emptied a tank before the residual crossed its threshold, and replay and bias-injection attacks were never detected. These show a model-based residual alone is not enough, and an extra independent measurement or a change to the plant is needed. The three-tank DTS200 is the standard fault-diagnosis benchmark, where several residuals let sensor and actuator faults be isolated.

### Cited Findings
- [F] Setup: four water tanks, two pumps and two level sensors (y1, y2). Flow ratios γ1 and γ2 split each pump's flow between tanks. The process has a non-minimum-phase configuration with an unstable zero. A remote LQG controller and a Kalman-filter anomaly detector run over a wireless network. — [Teixeira, Shames, Sandberg & Johansson, "A secure control framework for resource-limited adversaries", arXiv 1212.0226](https://ar5iv.labs.arxiv.org/html/1212.0226)
- [F] Results of the four attacks on that rig:
  - **Zero-dynamics attack on both actuators:** the residual rose only slightly. Tank 3 emptied after about 25 s. The residual crossed the threshold only after an actuator saturated, so detection came after the unsafe state.
  - **Replay on sensor 2 plus physical water theft from tank 4:** residual stayed below threshold. Not detected.
  - **Bias injection on actuator 1 and sensor 1** (ramped in slowly): tank 4 overflowed. Not detected.
  - **DoS on both sensors** (90% packet loss, controller holds last value): residual stayed below threshold. The paper notes missing data is trivially visible but could be mistaken for poor network conditions.
  
  — [arXiv 1212.0226](https://ar5iv.labs.arxiv.org/html/1212.0226)
- [S] Follow-up work: zero-dynamics attacks are not completely stealthy if the system starts from a non-zero initial condition, and they can be revealed by modifying the system's structure. — [Teixeira et al., "Revealing stealthy attacks in control systems"](https://typeset.io/pdf/revealing-stealthy-attacks-in-control-systems-2ip7hcyi3d.pdf)
- [S] A separate paper gives an index for the minimum number of sensors that must be attacked for a sensor attack to be undetectable, with a quadruple-tank example. — [ICASSP 2015](https://unpaywall.org/10.1109%2FICASSP.2015.7178271)
- [K] Topology detail, not verified: each pump feeds one lower tank and the diagonally opposite upper tank, upper tanks drain into lower tanks, only lower levels are measured, and γ1 + γ2 < 1 gives the non-minimum-phase case. — [Johansson, IEEE TCST 2000](https://doi.org/10.1109/87.845876)
- [S] The DTS200 three-tank pilot plant is a standard fault-diagnosis benchmark covering sensor and actuator faults. Published methods include a structured residual generator that isolates and estimates sensor and actuator faults, observer-based isolation, and work showing that the choice of measured outputs changes which faults are isolable. — [Theilliol et al., ISA Trans. 2002 (record)](https://research.uaeu.ac.ae/en/publications/fault-diagnosis-and-accommodation-of-a-three-tank-system-based-on/); [variogram-based diagnosis, PubMed](https://pubmed.ncbi.nlm.nih.gov/22369877/); [flat-output isolability, arXiv 2207.13803](https://arxiv.org/abs/2207.13803)
- [K] DTS200 layout, not verified: three cylindrical tanks in series (T1–T3–T2) joined by pipes with valves, pump 1 into T1, pump 2 into T2, outflow from T2, a manual leak valve on each tank, three level sensors. Typical faults are tank leaks, clogged connecting pipes, pump faults and sensor faults. — [Blanke et al., *Diagnosis and Fault-Tolerant Control*](https://doi.org/10.1007/978-3-662-47943-8)

### Inferences
- **Why one tank is not enough:** a single tank with one level and one inflow gives one mass-balance residual. Leak, inflow-meter bias, level-sensor drift and a level spoof all move that one residual. Three tanks give one balance per tank, and each fault excites a different subset: a T1 leak moves only T1's residual, and a clogged T1–T3 pipe moves two. That pattern is what isolates the cause. (This signature reasoning is the standard structural argument and was not checked against a specific published table.)
- **Why coupling separates faults from attacks:** a real leak in T1 changes the flow into the next tank, so the neighbour sees it. A spoofed T1 level changes nothing physical, so the neighbour's residual stays quiet while T1's jumps. To hide, the attacker must spoof both levels consistently.
- **Lesson for the project's stealth spoof and replay:** Teixeira's replay and bias attacks beat a Kalman residual detector on a real rig. The project's mass-balance check alone would be beaten the same way. Detection comes from sensor B, watermark probes and network counters. The demo could show exactly this: residual-only misses the replay, sensor B catches it.
- **DoS vs fault ambiguity:** Teixeira's remark that DoS looks like a bad network is a fault/attack ambiguity the project already has (DoS vs power loss or comms fault). The power monitor is the tie-breaker.
- **Concrete extension:** add tank T2 downstream through a valved pipe, with its own networked level sensor. That gives three balances (T1, T2, pipe flow), enough to separate leak, pipe clog, sensor drift and single-sensor spoof without relying on a trusted hard-wired sensor.

### Gaps
- No DTS200 source with a leak/clog fault-signature table was retrieved.
- Johansson's 2000 paper and the γ condition were not verified.

---

## Q7. What to borrow for the single tank (synthesis)

### Takeaway
In rough order of benefit for cost:
1. Add a second tank in series with its own controller (SWaT, DTS200).
2. Let a controller act on a level reported by another controller (C-Town).
3. Check command against position on every actuator (HAI).
4. Add setpoint/parameter injection and reconnaissance attacks (Morris).
5. Keep valve watermarking and sensor B as the answer to replay (WADI, quadruple tank).

### Cited Findings
- [F] Replay hides an attack only when nearly all sensors are replayed (at least 40 of 43 on BATADAL). Partial replay raises detection. — [arXiv 1907.07487](https://ar5iv.labs.arxiv.org/html/1907.07487)
- [F] On a real quadruple-tank rig, replay and slow bias injection were not detected by a residual detector. — [arXiv 1212.0226](https://ar5iv.labs.arxiv.org/html/1212.0226)
- [S] SWaT invariants may combine conditions from several stages, and the checks can run inside each PLC. — [arXiv 1809.04786](https://arxiv.org/pdf/1809.04786)
- [F] Separating disturbances from intrusions with process and controller data alone works only "to a certain extent" on TEP. — [arXiv 1706.01679](https://arxiv.org/abs/1706.01679)
- [V] No public water-tank dataset labels both faults and attacks. — project note `datasets_and_ml.md`, citing [UAH](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets)

### Inferences
- Topology feature → detection idea:

| Source | Topology feature | Idea for "Fault or Attack" |
|---|---|---|
| SWaT | 6 stages, PLC + backup per stage, ring to devices, star between PLCs | Cross-stage mass balance and state rules; checks run in each controller |
| WADI | Raw tanks → elevated reservoirs → 6 consumer tanks | Valve watermark probes; supply vs demand balance |
| C-Town / BATADAL | 7 tanks, 11 pumps, 9 PLCs, remote-level control | Pump ON ⇒ remote tank rises; partial replay exposes itself |
| HAI | 3 vendor controllers coupled by HIL setpoints | Command vs position; coordinated change with no physical cause |
| EPIC | Power plant feeding SWaT and WADI | Independent view of the power supply |
| TEP | 5 units with recycle, 41 meas / 12 MV | Fault spreads consistently; spoof is one odd variable |
| Morris tank / pipeline | One tank or pipeline, Modbus | Setpoint injection, recon; avoid label leakage |
| DTS200 | 3 tanks in series | Residual pattern isolates leak, clog, sensor fault |
| Quadruple tank | Cross-coupled tanks, 2 sensors for 4 states | Residual-only detection fails; need extra sensor or watermark |

- A two-tank, two-controller version adds three things the single tank lacks: a residual pattern in place of a single residual, a signal the attacker must also falsify, and a second controller whose view can be compared with the first.

### Gaps
- Items tagged [K] still need checking against primary papers, mainly SWaT stage tags, Morris attack-class names, and the quadruple-tank and DTS200 layouts.
- No source was found that tests fault-vs-attack discrimination on a coupled-tank rig directly. The argument above combines fault-isolation and attack-detection results from separate papers.
