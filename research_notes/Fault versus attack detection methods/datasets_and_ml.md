# Data-driven anomaly and attack detection for ICS: public datasets and methods

Scope: public ICS security datasets and the statistical/ML detectors evaluated on them, aimed at a small standard-library Python prototype ("Fault or Attack": tank, pump, on/off controller, sensors A/B, motor feedback, outflow, power, packet counts; 6 faults + 4 attacks: FDI, replay, command injection, DoS). Research done 2026-11-08 with about 20 tool calls; several numbers could only be confirmed from secondary sources, and those are flagged.

## Q1. Main public ICS security datasets: publisher, access, size, attacks, faults, licence

### Takeaway
The easiest datasets to start with are HAI (open on GitHub/Kaggle, physical process data, tens of attacks), the Morris/UAH power-system set (free download, labels natural faults and attacks separately), and the Kaspersky TEP attack set. SWaT and WADI are the best-known benchmarks, but you have to request them from iTrust (SUTD), they cannot be redistributed, and their labels have known problems. Of the datasets checked, only the Morris power-system set clearly labels both faults and attacks.

### Cited Findings

**SWaT (Secure Water Treatment), iTrust, Singapore University of Technology and Design (SUTD)**
- Access: you request it through a form on iTrust's site, and processing can take up to three working days. Requesters agree to terms that include acknowledging iTrust in publications and not redistributing the data. — [iTrust dataset page (via search summary)](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/); [SWaT page](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/swat/)
- SWaT.A1 (Dec 2015), the usual benchmark: 11 days of continuous operation (7 normal, 4 with attacks), 51 sensors/actuators labelled normal/abnormal, network traffic also captured. iTrust says 41 attacks were launched over the 4 days. — [iTrust SWaT page](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/swat/)
- Attack-count conflict: a SoK paper and a MathWorks example give 36 attacks (MitM between PLC and SCADA) for the same release, against iTrust's 41. — [SoK: Evaluations in Industrial Intrusion Detection (arXiv 2311.02929)](https://arxiv.org/pdf/2311.02929); [MathWorks example](https://uk.mathworks.com/help/predmaint/ug/water-treatment-anomaly-detection.html)
- Other releases: A2 (Sep 2018, 7 days normal); A3 (Jun 2017, 136 h normal plus network and historian data); A4/A5 (Jul 2019, 3 h normal + 1 h with 6 attacks); A6 (Dec 2019, 6 malware attacks, with PCAP and historian data); A7 (Jun 2020, normal); A9 (Dec 2023, 105 h normal for SWaT and WaDi, about 429 GB of PCAPs for SWaT). — [iTrust SWaT page](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/swat/)
- Label quality: one evaluation found consistent root-cause labels for only 33 attacks. For one attack, the start and end times did not match any event on the official attack list. — [search summary of arXiv 2109.11428 and related work](https://arxiv.org/pdf/2109.11428)
- Faults: SWaT has no labelled physical faults. During the 2023 run, a WaDi flow was set to 0 "to avoid triggering a faulty sensor", which shows real faulty sensors exist in the plant but are not labelled. — [iTrust SWaT page](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/swat/)

**WADI (Water Distribution), iTrust SUTD**
- Same request form and terms as SWaT. The 2023 WaDi.A3 100-hour run is normal operation only (about 335 GB of PCAPs plus historian data). — [iTrust SWaT page](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/swat/)
- The GDN paper uses 127 features, 118,795 training and 17,275 test samples after downsampling to 10 s, with a 5.99% anomaly rate in the test set. SWaT in the same paper: 51 features, 47,515 / 44,986 samples, 11.97% anomalies. — [Deng & Hooi, GDN, AAAI 2021 (arXiv 2106.06947)](https://ar5iv.labs.arxiv.org/html/2106.06947)

**HAI (HIL-based Augmented ICS), National Security Research Institute (NSR) / ETRI, South Korea**
- The testbed is a real ICS augmented with a hardware-in-the-loop simulator that emulates steam-turbine power generation and pumped-storage hydropower. HAI 1.0 was released on GitHub and Kaggle in Feb 2020. Later versions are 21.03, 22.04 and HAI/HAIEnd 23.05. — [HAI 1.0 paper, USENIX CSET 2020](https://www.usenix.org/conference/cset20/presentation/shin); [github.com/icsdataset/hai](https://github.com/icsdataset/hai)
- Access: open download from GitHub (some versions need `git lfs pull`) and from Kaggle, with no request form. — [search summary of the HAI repo](https://github.com/icsdataset/hai)
- HAI 22.04 (official README as reported in search): 3 training files (26, 56 and 35 h, normal only) and 3 test files (24, 23 and 17 h) with 7, 17 and 10 attacks (34 in total). Per-process attack labels were dropped from 22.04 onwards. Data is sampled at 1 Hz. An unofficial mirror gives different totals (6 training files, 279 h, 58 attacks), so check the repo directly. — [HAI repo](https://github.com/icsdataset/hai); [mirror](https://github.onedrive11.workers.dev/saurf4ng/hai)
- Training files contain no attacks. The maintainers say training data can only be collected during normal operation. — [HAI GitHub issue](https://github.com/icsdataset/hai/issues/1)
- Licence: a fork says CC BY-SA 4.0. I could not confirm this on the official repo (the GitHub fetch timed out). — [fork README](https://github.onedrive11.workers.dev/saurf4ng/hai)
- HAI 21.03 and the HAICon 2020/2021 anomaly-detection contests are described in CSET 2021. — [Two ICS Security Datasets and Anomaly Detection Contest (CSET 2021)](https://cset21.isi.edu/papers/cset21-1.pdf)
- Faults: I found no evidence that HAI labels physical faults. Its labels are attack/normal only. — [search summary](https://github.com/icsdataset/hai)

**BATADAL (Battle of the Attack Detection Algorithms), Taormina, Galelli, Tippenhauer et al.**
- A 2017 competition on the simulated C-Town water distribution network (PLCs plus SCADA). Seven teams took part, and entries were scored on time-to-detection and classification accuracy. Published in J. Water Resources Planning and Management, 2018 (paywalled). — [Bath research portal](https://researchportal.bath.ac.uk/en/publications/battle-of-the-attack-detection-algorithms-disclosing-cyber-attack/); [ASCE](https://ascelibrary.com/doi/10.1061/%28ASCE%29WR.1943-5452.0000969)
- Structure: two training sets (one with no attacks, one partially labelled) and a 3-month unlabelled test set containing several attacks. Hourly SCADA readings. Free download; it is indexed by the WaterFutures benchmark hub. — [WaterBenchmarkHub BATADAL](https://waterfutures.github.io/WaterBenchmarkHub/benchmarks/BATADAL.html); [readthedocs](https://waterbenchmarkhub.readthedocs.io/en/dev/water_benchmark_hub.batadal.html)

**Tennessee Eastman Process (TEP)**
- Kaspersky (Filonov, Kitashov, Lavrentyev, arXiv 1709.02232) simulated TEP under cyberattacks and released the data. The attacks target measurements (MEAS), manipulated variables (MV) and setpoints. The attack types are integrity (false values), DoS (value frozen for the duration) and noise. The test set has 142 attack samples. — [arXiv 1709.02232](https://arxiv.org/pdf/1709.02232)
- Reinartz, Kulahci & Ravn (2021, DTU) is a faults-only extended TEP set: 28 process faults across 6 operating modes, each fault simulated 500 times. — [DTU data](https://data.dtu.dk/articles/dataset/Tennessee_Eastman_Reference_Data_for_Fault-Detection_and_Decision_Support_Systems/13385936)
- Rieth et al. 2017 (Harvard Dataverse doi:10.7910/DVN/6C3JR1) has 20 TEP faults used as anomaly labels and no attacks. — [TimeSeAD docs](https://timesead.readthedocs.io/en/latest/autoapi/timesead/data/tep_dataset/index.html)
- An IEEE DataPort entry by Khan labels 8 cyber-physical attack classes on TEP. Some DataPort content needs an IEEE login. — [IEEE DataPort TEP](https://ieee-dataport.org/documents/tennessee-eastman-process-dataset)

**Morris / Mississippi State / UAH datasets (Tommy Morris; power-system set with Oak Ridge National Laboratory)**
- All are free downloads from the UAH page. No licence is stated, only citation requests. — [UAH ICS data sets](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets)
- **Power system** (synchrophasor data plus Snort, control panel and relay logs): 37 scenarios. One breakdown is normal (1), line maintenance (2), short-circuit fault (6), remote tripping command injection (6), relay setting change (16) and data injection (6). Another source groups them as 1 normal, 8 natural events and 28 attacks. Offered in 2-class (natural+normal vs attack), 3-class and multi-class versions. — [UAH page](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets); [CRUPL arXiv 2503.00358 (via search)](https://arxiv.org/pdf/2503.00358)
- **Gas pipeline and water storage tank** (Morris & Gao, network traffic in ARFF format): the authors warn that the data contains unintended patterns, such as attack-specific pressure values, that let ML models cheat. — [UAH page](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets)
- **New gas pipeline** (Morris, Thornton & Turnipseed 2015) adds more randomness to fix those patterns. The page also lists a 30-day anonymized EMS log set. — [UAH page](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets)

**Electra (Perales Gómez et al., University of Murcia, IEEE Access 2019)**
- Network traffic from an electric traction substation (PLCs plus SCADA over S7Comm and Modbus) under normal and attack conditions. The methodology covers attack selection, deployment, capture and feature computation. A review reports 7 devices and about 1.7 GB of S7 traffic plus 56 MB of Modbus traffic. Sources disagree on whether the network was real or simulated. — [Univ. Murcia repository](https://digitum.um.es/digitum/bitstream/10201/142731/1/On_the_Generation_of_Anomaly_Detection_Datasets_in_Industrial_Control_Systems.pdf); [arXiv 2208.08255 review](https://arxiv.org/pdf/2208.08255)

**Field-level context**
- A SoK of 609 industrial intrusion-detection papers found that papers evaluate on only 1.3 datasets on average and that common metrics are ambiguous. — [SoK arXiv 2311.02929](https://arxiv.org/abs/2311.02929)

### Inferences
- **Practicality for a small team (TRL 4 validation):**
  - **HAI: easiest physical-process option.** Open download, CSV at 1 Hz, normal-only training data, a few hundred MB per version (size inferred, not verified). Its process (boiler, turbine and water treatment loops with level/flow control) is close to a tank-and-pump model.
  - **Morris power system set: the only fault-plus-attack labelled set.** Directly useful for showing fault-vs-attack separation, but the domain is power relays rather than a tank.
  - **Morris gas pipeline / water tank: closest to the tank, but flawed.** Its labels leak through the data, so any good score is suspect. Use the "new gas pipeline" version instead.
  - **BATADAL: easy, but hourly and simulated.** Coarse resolution.
  - **TEP: easy.** Fault sets (DTU, Dataverse) and the attack set (Kaspersky) come from the same simulator family, so fault and attack data could be combined, with caveats about mismatched simulation settings.
  - **SWaT/WADI: highest credibility, but slowest.** You need the request form and agreement, cannot redistribute, and the files are large.
- A pragmatic TRL-4 path: replay HAI test CSVs, or a single SWaT process stage, through the existing rule-based detector's input interface and report event-wise detection. Separately, use the Morris power set to show fault-vs-attack labelling.

### Gaps
- WADI's original attack count and duration (often cited as 16 days with about 15 attacks) were not confirmed from a primary source in this session.
- The exact HAI licence on the official repo and HAI 23.05 / HAIEnd specifics are unverified.
- Electra's attack list and access method (open download or request) were not confirmed.
- BATADAL's winning team scores were not retrieved (the paper is paywalled).

## Q2. Detection methods evaluated on these datasets: reported accuracy and ease of implementation

### Takeaway
Reported F1 on SWaT ranges from about 0.2 to 0.8 depending on the method and protocol. Simple baselines (PCA reconstruction, per-channel Gaussian scoring, invariant rules) are often competitive once evaluation is done honestly. For a standard-library prototype, the best options are residual-based checks (predict, subtract, then CUSUM or a z-score), mined invariant rules, and PCA on a few correlated signals.

### Cited Findings
- **GDN (graph deviation network; learned sensor graph plus forecasting deviation), Deng & Hooi, AAAI 2021.** Point-wise results with no point-adjust mentioned. The threshold is the maximum smoothed score on validation data. Data is downsampled to 10 s medians and the first 2,160 samples are dropped. — [ar5iv 2106.06947](https://ar5iv.labs.arxiv.org/html/2106.06947)

  | Method | SWaT precision | SWaT recall | SWaT F1 | WADI precision | WADI recall | WADI F1 |
  |---|---|---|---|---|---|---|
  | PCA | 24.92% | 21.63% | 0.23 | 39.53% | 5.63% | 0.10 |
  | KNN | 7.83% | 7.83% | 0.08 | 7.76% | 7.75% | 0.08 |
  | Feature Bagging (FB) | 10.17% | 10.17% | 0.10 | 8.60% | 8.60% | 0.09 |
  | Autoencoder | 72.63% | 52.63% | 0.61 | 34.35% | 34.35% | 0.34 |
  | DAGMM | 27.46% | 69.52% | 0.39 | 54.44% | 26.99% | 0.36 |
  | LSTM-VAE | 96.24% | 59.91% | 0.74 | 87.79% | 14.45% | 0.25 |
  | MAD-GAN | 98.97% | 63.74% | 0.77 | 41.44% | 33.92% | 0.37 |
  | GDN | 99.35% | 68.12% | 0.81 | 97.50% | 40.19% | 0.57 |

  Some baseline numbers are copied from Li et al. 2019 rather than re-run.
- **1D CNN prediction-residual detector, Kravchik & Shabtai 2018 (SWaT).** Detected 31 attacks with 3 false positives. The authors say 1D CNNs beat larger recurrent networks while being smaller and faster to train. — [arXiv 1806.08110](https://arxiv.org/abs/1806.08110v2)
- **Lightweight NNs and PCA, Kravchik & Shabtai, IEEE TDSC 2021.** Uses 1D CNNs, shallow undercomplete autoencoders, VAEs and PCA, all unsupervised. The headline F1 was not retrieved. — [search result citing the paper](https://archive.cps-vo.org/node/60817)
- **Data-driven invariants, Feng et al., NDSS 2019 (SWaT).** Mines invariant rules from normal logs (control dynamics plus data mining). It derives many more meaningful rules than manual design, and the slides claim zero false positives. — [NDSS paper page](https://ndss-symposium.org/ndss-paper/a-systematic-framework-to-generate-invariants-for-anomaly-detection-in-industrial-control-systems); [slides](https://www.ndss-symposium.org/wp-content/uploads/ndss2019_07A-3_Feng_slides.pdf)
- **Design-based invariant checkers on SWaT/WADI.** Reported to detect single- and multi-stage attacks without false positives. — [InvarLLM arXiv 2411.10918 (related-work summary)](https://arxiv.org/html/2411.10918v2)
- **InvarLLM (LLM-extracted physical invariants).** Claims 100% precision with no false alarms on SWaT and WADI (authors' own claim). — [arXiv 2411.10918](https://arxiv.org/html/2411.10918v2)
- **Association-rule invariant mining with temporal predicates.** Zhu et al., Control Engineering Practice 2024. — [Reading repository PDF](https://centaur.reading.ac.uk/119776/1/Control%20Engineering%20Practice%202024.pdf)
- **Audibert et al., Pattern Recognition 2022.** Compared 16 conventional, ML and deep methods on 5 open datasets: "no family of methods outperforms the others". Conventional methods win when training data is small. — [arXiv 2204.01637](https://www.arxiv.org/abs/2204.01637); [EURECOM](https://www.eurecom.edu/en/node/4901236)
- **Garg et al. (arXiv 2109.11428).** Tested 10 deep models × 4 scoring functions on CPS data. The scoring function often mattered more than the model, and dynamic scoring beat static. The best performer was a channel-wise (univariate) fully-connected autoencoder with a dynamic Gaussian scoring function. — [arXiv 2109.11428](https://arxiv.org/abs/2109.11428)
- **RNN prediction-error detection on TEP.** Filonov et al. (Kaspersky) use forecasting residuals for early attack detection. — [arXiv 1709.02232](https://arxiv.org/pdf/1709.02232)

### Inferences
- PCA's low F1 in the GDN table (0.23 on SWaT) contrasts with Audibert's finding that conventional methods are competitive. This suggests baseline results depend heavily on tuning, windowing and thresholding, so a weak baseline in someone else's table is not proof that the method is weak.
- Simplest to add to a standard-library Python detector, in order of payoff:
  1. **Residual plus CUSUM:** predict each sensor from a simple model (previous value, or tank mass balance: level change ≈ inflow from pump state − outflow), then run a two-sided CUSUM on the residual. This is what the CNN/LSTM residual methods do, with a hand-built physics predictor instead of a network.
  2. **Mined invariants (Feng-style):** learn rules from normal runs, such as "pump ON ⇒ level rising and power > P_min" or "|sensor A − sensor B| < δ". Implement them as threshold checks.
  3. **Per-channel rolling z-score or Gaussian scoring:** a cheap approximation of Garg et al.'s "dynamic Gaussian scoring", which worked well there.
  4. **PCA on a handful of channels:** about 5–8 variables, using power iteration on the covariance matrix, which is feasible in pure Python. Score with Q/SPE (squared prediction error) and Hotelling T².
- Autoencoders, LSTM-VAE, MAD-GAN and GDN need numpy or torch and labelled tuning. They are not worth it for a standard-library prototype.

### Gaps
- I did not retrieve exact F1 values for Kravchik & Shabtai (TDSC 2021), Feng et al. NDSS 2019, isolation forest, one-class SVM, USAD or TranAD on SWaT/HAI.
- HAICon contest winning scores (which use the TaPR metric) were not retrieved.

## Q3. Methods and datasets that separate faults from attacks

### Takeaway
Almost all of the SWaT, WADI, HAI and BATADAL literature is plain anomaly detection (normal vs attack). Explicit fault-vs-attack work is rare. It relies on cross-checking cyber evidence (network or log anomalies) against physical evidence, and the Morris power-system set is the main public dataset with labelled natural faults alongside attacks.

### Cited Findings
- **arXiv 2601.03289 (2026).** Separates faults from cyberattacks in distributed energy resource (DER) systems by combining cyberspace logs with physical measurements. The authors say this is harder than anomaly detection, which only flags abnormalities. Case studies cover false-data injection, system faults and memory-corruption attacks. — [arXiv 2601.03289](https://arxiv.org/pdf/2601.03289)
- **"Fault Tolerance vs. Attack Detection in ICS: A Deep Learning Approach" (Boise State, TEP).** Fault masking improves stability but lowers attack-detection recall, and PCA shows heavy overlap between faulty and attack states in feature space. — [Boise State](https://experts.boisestate.edu/en/publications/fault-tolerance-vs-attack-detection-in-industrial-control-systems/)
- **Morris power-system dataset.** Includes short-circuit faults and line maintenance (natural events) alongside command-injection, relay-setting and data-injection attacks, with a 3-class/multi-class labelling built for this discrimination. In that testbed, relays have no internal validation, so breakers trip whether a fault is natural or attacker-created. — [UAH page](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets); [search summary](https://arxiv.org/pdf/2503.00358)
- **TIB simulation dataset.** A dataset record describes simulation results for distinguishing physical faults from cyberattacks. Few details are available. — [TIB service](https://service.tib.eu/ldmservice/group/results)
- **Physical signals alone can mislead.** Process-variable changes can come from normal transients, incipient faults or degradation, and many attacks show up as malfunctions or faults. — [arXiv 2305.09678 (via search)](https://arxiv.org/pdf/2305.09678v1.pdf)
- **TEP gives both faults and attacks, from separate simulator runs:** faults from DTU/Reinartz (28) and Dataverse/Rieth (20), attacks from Kaspersky. — [DTU](https://data.dtu.dk/articles/dataset/Tennessee_Eastman_Reference_Data_for_Fault-Detection_and_Decision_Support_Systems/13385936); [arXiv 1709.02232](https://arxiv.org/pdf/1709.02232)

### Inferences
- The prototype's approach of corroborating physical evidence with cyber evidence (packet counts, command provenance, sensor A vs B, motor feedback vs commanded state) matches the 2026 DER paper's cyber-plus-physical idea and is a defensible novelty claim.
- For validation, the Morris power set (natural vs attack classes) and a TEP fault set plus attack set are the realistic options for demonstrating the FAULT vs ATTACK label specifically.

### Gaps
- No ICS process dataset close to the tank (water, HAI) with labelled faults and attacks was found.
- I did not retrieve per-class accuracy figures for fault-vs-attack discrimination on the Morris dataset.

## Q4. Known evaluation pitfalls

### Takeaway
Point-adjust (PA) scoring can make even random scores look state-of-the-art. Threshold tuning on test data, label errors (in SWaT especially) and single-dataset evaluation are widespread. Report event-wise or range-based metrics with thresholds fixed on normal or validation data.

### Cited Findings
- **Point-adjust inflation.** Under PA, a random anomaly score can reach state-of-the-art results, and an untrained model performs comparably to existing methods even without PA. The authors propose a new baseline and evaluation protocol. — Kim et al., AAAI 2022 ([AAAI](https://ojs.aaai.org/index.php/AAAI/article/view/20680); [arXiv 2109.05257](https://export.arxiv.org/abs/2109.05257))
- **Metrics that cannot spot trivial detectors.** Existing metrics either ignore events or cannot tell a good detector from a random or all-positive one, so the authors propose a composite F-score (event-wise recall combined with point-wise precision). — Garg et al. ([arXiv 2109.11428](https://arxiv.org/abs/2109.11428))
- **Range metrics and label fixes.** Range-F1 describes performance better than point-F1, and corrections to SWaT labels are recommended. — [Springer reconstruction-based ICS study (via search)](https://unpaywall.org/10.1007%2F978-3-031-17143-7_24)
- **Binary metrics hide behaviour differences.** On SWaT, macro F1 falls from 85.44% (binary) to 37.84% when predicting behaviour-proxy classes. WADI is dominated by repetition, while SWaT shows stealthier frozen-telemetry behaviour. — [arXiv 2606.30493](https://arxiv.org/pdf/2606.30493)
- **Training-time contamination.** Robustness of ICS detectors when normal training data contains anomalies is studied in [arXiv 2608.23547](https://arxiv.org/pdf/2608.23547).
- **Protocol-dependent rankings.** Detector rankings shift with metric choice, hyperparameter handling and protocol, and temporal leakage and split construction are recurring issues. — [arXiv 2408.03747 (via search summary)](https://arxiv.org/pdf/2408.03747)
- **Ambiguous metrics and few datasets.** Papers evaluate 1.3 datasets on average, and newer metrics have seen little uptake. — [SoK arXiv 2311.02929](https://arxiv.org/abs/2311.02929)
- **Dataset artefacts.** The Morris gas pipeline and water tank data contains attack-specific values that let classifiers cheat. — [UAH page](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets)
- **Preprocessing choices change results.** For example, GDN removes the start-up period and downsamples with majority labels. — [ar5iv 2106.06947](https://ar5iv.labs.arxiv.org/html/2106.06947)

### Inferences
- For the hackathon, report these with a fixed protocol: thresholds set only from normal or training runs; per-event detection rate; false alarms per hour of normal data; detection delay; and FAULT/ATTACK confusion on detected events. Do not use point-adjust, and say so explicitly.
- Include a random-score baseline and a "always FAULT" baseline to show the metrics can tell them apart (Kim et al., Garg et al.).

### Gaps
- I did not retrieve the exact HAI/HAICon TaPR metric definition or its recommended settings.
