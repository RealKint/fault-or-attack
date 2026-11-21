# Sensing and Detection Topologies for Telling Faults from Attacks (incl. Pipeline Leak Localization)

**How to read the evidence tags.** Every finding carries one of three tags.
- **[V-full]**: checked this session against the paper's own text.
- **[V-abs]**: checked this session against the abstract, a bibliographic page or a search-result summary only. The detail beyond the abstract is not confirmed.
- **[MEMORY]**: not checked this session. It comes from the researcher's prior knowledge and links to a Google Scholar title search so it can be verified. Do not quote numbers from [MEMORY] items without checking.

Vendor or blog sources are labelled as such. The PHMSA final report PDF returned HTTP 403, so the PHMSA figures below come from the October 2012 webinar and industry comments on the draft, not from the final report.

## 1. Redundant and diverse sensing (TMR / 2oo3, analytical redundancy, diverse physics)

### Takeaway
Our A-vs-B pair can detect a disagreement but cannot say which sensor is wrong. A third channel fixes that, and it can be a "virtual" one: a model-based estimate of level from actuator feedback and the outlet flow meter. Different sensor physics lowers common-cause failure and forces a spoofer to falsify several independent paths consistently.

### Cited Findings
- **[V-abs]** A 2oo3 architecture has a hardware fault tolerance (HFT) of 1, and redundancy is not the same as HFT. — [PTQ Q2 2024](https://ptqmagazines.digitalrefining.com/view/747650962/93/)
- **[V-abs, vendor]** Diversity lowers the common-cause beta factor compared with identical redundancy. Common-cause failures of diverse channels are less likely to happen at the same time, which helps diagnostics catch them. — [ABB, "Diverse Redundancy" value paper](https://library.e.abb.com/public/c8ebe6fed0204975852575ac0061e959/1462_DiverseRedundancy_Final.pdf)
- **[V-abs, trade press]** Adding more identical transmitters (e.g., going to triple redundancy) gives little benefit when a common cause such as density variation dominates. Radar resists some common causes of differential-pressure (dP) level measurement, such as impulse-line plugging. Radar in turn can be weakened by vapor, agitators and foam, so dP can back up radar. — [Chemical Engineering, "Safety instrumented systems: focus on measurement diagnostics"](https://chemengonline.com/safety-instrumented-systems-focus-on-measurement-diagnostics)
- **[V-abs, blog; rule of thumb]** Many plants use a common-cause beta factor of 1.0–5.0% for approved devices with good engineering practice. It can be much higher otherwise. — [InstrumentationTools](https://instrumentationtools.com/?p=55445)
- **[V-abs]** Pasqualetti, Dörfler & Bullo model cyber-physical systems as linear descriptor systems and attacks as unknown inputs. The model covers stealth, false-data injection and replay attacks. They give algebraic and graph-theoretic conditions for undetectable and unidentifiable attacks, and limits for static, dynamic and active monitors. Their examples include a municipal water supply network. — [arXiv 1202.6144](https://arxiv.org/abs/1202.6144)
- **[V-full]** Urbina et al. (ACM CCS 2016) found, across simulations, testbeds and real data:
  - stateful tests (CUSUM) limit a stealthy attacker's impact better than stateless per-sample thresholds at the same false-alarm level;
  - linear state-space models beat output-only autoregressive models;
  - models that use correlation across time and across signals beat per-signal models;
  - undetected actuator attacks are harder for the attacker than undetected false sensor data.
  — [Urbina et al., CCS 2016 (PDF)](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- **[V-full]** In the same paper's simulated test, an actuator attack (the pump ignores "Off" and reports back "Off" while actually On) was caught only by the stateful test, with both tests tuned to a false-alarm probability of 0.01. In the water-tank experiment, 20 undetected attacks of about 40 minutes each could spill a large amount of water under stateless detection (the tank overflows at 0.3 m). Stateful detection limited the impact. — [Urbina et al.](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- **[MEMORY]** Liu, Ning & Reiter (CCS 2009): a false-data injection a = Hc (in the column space of the measurement matrix H) passes the residual bad-data detector in power-system state estimation, so the attacker must compromise a specific set of meters. — [Scholar search](https://scholar.google.com/scholar?q=Liu+Ning+Reiter+False+data+injection+attacks+against+state+estimation+electric+power+grids)
- **[MEMORY]** Classic analytical-redundancy fault diagnosis (parity equations, observers, structured residuals): Chen & Patton 1999; Isermann 2006. — [Scholar search](https://scholar.google.com/scholar?q=Chen+Patton+Robust+Model-Based+Fault+Diagnosis+for+Dynamic+Systems)

### Inferences
- **Three-channel vote for the tank sim.** Use level A (network), level B (hard-wired, different physics) and a virtual level L̂ from a Kalman filter or simple observer. Drive L̂ from the actuator *feedback* and the outlet flow meter. Compare the three pairwise differences:
  - only A disagrees: A is faulty or spoofed;
  - only L̂ disagrees: process problem (leak, or flow meter / actuator wrong);
  - everything disagrees: multiple problems.
- **Diversity as a fault-vs-attack clue.** A physical sensor fault follows that sensor's physics (foam on radar, plugged line on dP, stuck float). A network attack shows only on the networked channel. A deviation confined to the networked channel, with the hard-wired sensor and the model in agreement, points to a cyber cause.
- **Swap the per-sample threshold for CUSUM.** Urbina's result maps directly onto our tank. A per-sample threshold lets an attacker shift the level by just under the threshold at *every* step. CUSUM caps the total undetected drift.
- **Use one correlated model.** A single state-space model over level, inflow and outflow should beat separate per-signal checks (Urbina findings c and d).
- **Game mechanic.** Attacker cost = number of channels that must be falsified consistently (the a = Hc idea).

### Gaps
- No source found that quantifies a mixed-technology 2oo3 (e.g., radar + dP + float) failure probability. Beta figures are vendor/blog rules of thumb, not standard text.
- IEC 61508/61511 text itself was not consulted.

## 2. Detector placement: centralized vs. distributed/edge vs. network; secure state estimation

### Takeaway
A central detector sees only what the network delivers, so it can be fed the same false data as the controller. Secure-estimation theory gives a hard counting rule: correcting q attacked sensors needs more than 2q sensors' worth of independent information about every state direction, so fewer than half the sensors may be attacked. With one networked level sensor, our project is below this bound unless sensor B and the model channel are counted.

### Cited Findings
- **[V-full]** Fawzi, Tabuada & Diggavi, Proposition 2: a decoder can correct q attacked sensors after T steps if and only if, for every nonzero state z, the number of sensors that "see" z over those T steps is greater than 2q. Formally, |supp(Cz) ∪ supp(CAz) ∪ … ∪ supp(CA^(T−1)z)| > 2q. Lemma 1: when A has eigenvalues of distinct magnitudes, this reduces to |supp(Cv)| > 2q for every eigenvector v of A. The paper links this to q-error-correcting codes over the reals. — [arXiv 1205.5073](https://arxiv.org/pdf/1205.5073)
- **[V-abs]** The same paper (IEEE TAC 2014, vol. 59, pp. 1454–1467) proposes an estimator inspired by error correction over the reals and compressed sensing. It shows a separation principle between estimation and control holds. Its abstract addresses the case where more than half the sensors are attacked. — [arXiv abstract](https://arxiv.org/abs/1205.5073); [CPS-VO record](https://archive.cps-vo.org/node/19355)
- **[V-abs]** Later work notes that existing secure-estimation methods usually restrict the attacker to strictly fewer than half of the sensors. — [arXiv 2309.05075](https://arxiv.org/html/2309.05075v2)
- **[V-full]** Urbina et al. surveyed prior detection papers and observed that most use stateless tests, there is no consistent adversary model or metric, and no earlier work validated with simulations, testbeds and real data together. Their attacker is adaptive: if the threshold is lowered, the attack shrinks to stay under it. — [Urbina et al.](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- **[MEMORY]** Teixeira et al. (Automatica 2015) classify attacks by the attacker's model knowledge, disclosure resources and disruption resources. — [Scholar search](https://scholar.google.com/scholar?q=Teixeira+A+secure+control+framework+for+resource-limited+adversaries)
- **[MEMORY]** Shoukry et al. (SMT-based secure state estimation) and Pajic et al. (attack-resilient estimators robust to noise and model error) make the Fawzi approach practical. — [Scholar search](https://scholar.google.com/scholar?q=Shoukry+secure+state+estimation+satisfiability+modulo+theory); [Scholar search](https://scholar.google.com/scholar?q=Pajic+Robustness+of+attack-resilient+state+estimators)

### Inferences
- **Counting rule for our tank.** Level is one state. To survive q = 1 spoofed level channel, at least 3 channels must carry level information (A, B and the mass-balance model fed by the flow meter and actuator feedback). To survive q = 2, we need 5. This is a one-line design rule and a good slide.
- **Split the detector into three.**
  1. Edge check at the field device, before the network: range, rate-of-change, command-vs-feedback. It sends a signed flag.
  2. Central process detector: our mass balance and model.
  3. Network detector: our counters.

  Where the inconsistency appears is the clue:
  - edge says normal, central sees an anomaly: the data changed in transit, so attack;
  - edge and central see the same anomaly, network clean: physical fault;
  - edge flag fails its signature check: tampering.
- No verified source was found that measures centralized vs. edge detection latency, so this split is a design argument, not a measured result.

### Gaps
- No verified field data or vendor architecture for edge-level process anomaly detection.
- Pasqualetti's centralized-vs-distributed monitor designs (Part II of that paper) were not retrieved.

## 3. Physical watermarking and moving-target defenses; effect of topology

### Takeaway
Watermarking adds a small secret random signal to the control input and checks that the sensors respond to it. It catches replayed or counterfeit sensor data, at the price of some control performance or detection delay. Moving-target defense goes further by making the plant's dynamics secret and time-varying. More actuators and sensors give both methods more room to hide.

### Cited Findings
- **[V-abs]** Mo & Sinopoli, "Secure control against replay attacks" (Allerton 2009, pp. 911–918): a linear Gaussian system under an LQG controller with a chi-square failure detector. Detection probability at a fixed false-alarm rate can be raised by trading off detection delay or LQG performance. — [bibliographic record](https://search.isc.ac/inventory/49/3238687.htm); [CITRIS seminar abstract](https://citris-uc.org/trust-security-seminar-secure-control-against-replay-attacks/)
- **[V-abs]** Later papers describe the method as adding an i.i.d. Gaussian watermark to the LQG input, which changes the innovation statistics under replay so a chi-square detector fires. Follow-up work optimizes watermark power to maximize detection for a given LQG cost increase. — [arXiv 1908.00090](https://ar5iv.labs.arxiv.org/html/1908.00090); [arXiv 2101.01466](https://ar5iv.labs.arxiv.org/html/2101.01466)
- **[V-abs]** Mo, Weerakkody & Sinopoli, "Physical Authentication of Control Systems: Designing Watermarked Control Inputs to Detect Counterfeit Sensor Outputs", IEEE Control Systems Magazine 35(1):93–109, 2015. — [author page](https://yilinmo.github.io/papers/cms-15-replay.html)
- **[V-abs]** Weerakkody, Mo & Sinopoli (CDC 2014) consider an adversary who knows the system and can read a *subset* of real-time control inputs and sensor outputs, and propose a more robust watermark and detector. A later paper uses a Bernoulli-Gaussian watermark with random drops at the control input. — [WUSTL record](https://profiles.wustl.edu/en/publications/detecting-integrity-attacks-on-control-systems-using-robust-physi/); [researchr](https://researchr.org/publication/WeerakkodyOS17)
- **[V-abs]** Griffioen, Weerakkody & Sinopoli, "A Moving Target Defense for Securing Cyber-Physical Systems" (IEEE TAC 2021) target a model-aware adversary who can bypass bad-data detection. They add stochastic, time-varying parameters in three designs:
  - a hybrid design, where plant parameters switch among modes;
  - an extended design, where an auxiliary subsystem is coupled to the plant, does not affect performance, and has its own sensors that reveal attacks;
  - use of sensor nonlinearities.

  The dynamics should change fast enough to stop the attacker identifying the system. — [arXiv 1902.01423](https://arxiv.org/abs/1902.01423v2)
- **[V-abs]** Miao, Pajic & Pappas use a stochastic game to switch between a cost-optimal but insecure controller and a secure but costlier one under replay attack. — [paper PDF](https://typeset.io/pdf/stochastic-game-approach-for-replay-attack-detection-8tk0e8hykd.pdf)
- **[MEMORY]** Satchidanandan & Kumar, "Dynamic watermarking" (Proc. IEEE 2017): tests on watermark-measurement correlation limit an undetected attacker to zero-power distortion. — [Scholar search](https://scholar.google.com/scholar?q=Satchidanandan+Kumar+Dynamic+watermarking+active+defense+of+networked+cyber-physical+systems)

### Inferences
- **Topology effect.** The CDC 2014 adversary reads only a subset of inputs and outputs. With a single actuator and one networked sensor, as in our tank, that subset can be everything. Adding the hard-wired sensor B gives a channel where the watermark response cannot be forged from the network. Adding a second actuator (pump and valve) lets the watermark be a random 2-D vector.
- **Upgrade the "secret probe" pulses.** Replace fixed pulses with a pseudo-random binary sequence or Gaussian dither, and correlate it with the level-rate residual over a sliding window. The discriminator is clean:
  - a leak or actuator fault leaves the correlation intact, because the tank still responds, and only adds a bias;
  - replayed or synthesized sensor data loses the correlation.
- **Switchable watermark.** The game-theory result suggests turning the watermark on only when suspicion is raised, to save control cost. This could be a player choice with a cost.
- **Cheap moving target.** Add a small auxiliary element, such as a second small tank or a recirculation loop with its own sensor and secretly varying gain. It mirrors the "extended design".

### Gaps
- No verified numbers for detection rate vs. watermark power or LQG cost. The magazine article's full text was not retrieved.
- No source found that directly quantifies watermark strength vs. number of actuators/sensors. The topology argument above is inference.

## 4. Pipeline leak detection and localization topologies

### Takeaway
The game's per-section mass balance is a legitimate, simplified form of computational pipeline monitoring (CPM). It can only say *which section* leaks, and real balance systems are slow for small leaks. Timing a pressure wave at both ends of a section gives a point location. Fiber-optic sensing gives meter-scale location at much higher cost. Real-world CPM has a weak detection record, which supports teaching layered methods.

### Cited Findings
- **[V-abs]** 49 CFR 195.444 requires each CPM leak detection system on a hazardous liquid pipeline to comply with API RP 1130 for operation, maintenance, testing, records and dispatcher training. DOT adopted API 1130 into Part 195 in 1998, with compliance from 6 July 1999. — [Cornell LII, 49 CFR 195.444](https://www.law.cornell.edu/cfr/text/49/195.444); [Oil & Gas Journal](https://www.ogj.com/home/article/17230433/dot-mandates-api-document-for-leak-detection)
- **[V-abs]** CPM technologies listed in a Texas Railroad Commission presentation: volume balance, mass balance, statistical volume balance, rate-of-change, real-time transient model (RTTM) and pressure point analysis. — [RRC Texas presentation](https://rrc.texas.gov/media/g3blv1vv/leak-detection-cpm-alberto-hernandez.pdf)
- **[V-abs]** API RP 1130 notes that a volume-balance CPM cannot evaluate loss when there is no flow through the meters (line shut down), and that slack-line operation complicates use. — [API 1130 (2002 edition, public copy)](https://law.resource.org/pub/us/cfr/ibr/002/api.1130.2002.pdf)
- **[V-abs]** PHMSA/Kiefner leak detection study, October 2012 webinar: for hazardous liquid incidents from January 2010 to July 2012, CPM or SCADA was the initial identifier in 23 of 197 incidents (about 12%). Another slide gives 21 incidents (about 14.9%) on a different base. A summary slide says the pipeline controller identified 17% of releases on the right-of-way. — [Kiefner/PHMSA webinar slides](https://primis-meetings.phmsa.dot.gov/archive/Kiefner_PHMSA_Web_10-05-2012_(1)_PHMSA3.pdf)
- **[V-abs]** Industry comments on the draft state that CPM/SCADA identified about 12% of all releases but about 39% of larger-than-average releases. — [API/AOPL comments, Oct 2012](https://primis-meetings.phmsa.dot.gov/archive/Summary_Comments_Kiefner_PHMSA_Report_Oct_2012-10-26-12.pdf)
- **[V-abs, vendor figures; treat as indicative only]** One vendor's comparison:

| Method | Smallest leak | Location accuracy | Detection time | Sensor spacing |
|---|---|---|---|---|
| Negative pressure wave (NPW) | 1–3% of flow | ±50–200 m | 1–30 s | up to ~10 km |
| Flow balance | 3–5% of flow | section only | 1–4 h | at section ends |
| Acoustic | 0.5–2% of flow | ±100 m | 10–60 s | 500–2,000 m per sensor |
| Fiber optic (temperature) | 0.1–1% of flow | ±1–5 m | 1–10 min | one fiber covers 30–50 km |

  The same vendor quotes fiber at $50,000–200,000 per km, and NPW accuracy as about ±1–3% of sensor spacing. — [Rossma comparison](https://pipeline.rossma.ru/en/blog/comparison-leak-detection); [Rossma NPW article](https://pipeline.rossma.ru/en/blog/negative-pressure-wave)
- **[V-abs, vendor]** NPW accuracy depends mainly on clock synchronization between sensors, wave-speed calibration, signal-to-noise ratio and sampling rate. GPS timestamping is not always available in water networks. — [Rossma](https://pipeline.rossma.ru/en/blog/negative-pressure-wave); [Atmos International](https://www.atmosi.com/us/news-events/blogs/a-new-approach-to-water-leak-location-when-gps-timestamping-isn-t-available/)
- **[V-abs]** One distributed acoustic sensing (DAS) system reports measurement resolution of about 1.0 m, spatial resolution of about 10 m, and fibre lengths up to 100 km. This is a single system, not an industry range. — [Pipeline Technology Conference abstract](https://www.pipeline-conference.com/abstracts/identification-ground-heave-associated-pipeline-leaks-utilising-optical-fibre-based)
- **[V-abs]** Lab-scale academic NPW work exists (e.g., piezoceramic sensors with improved time resolution; a 55.8 m PVC test pipe), but no peer-reviewed spacing-vs-accuracy relation for field pipelines was found. — [PMC6540103](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC6540103/); [PMC11945569](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11945569/)
- **[MEMORY]** NPW location formula: with pressure sensors at both ends of a section of length L and wave speed a, the leak lies at x = (L + a·Δt)/2 from the upstream sensor, where Δt = t_up − t_down. Timing error δt gives a position error of about a·δt/2. — [Scholar search](https://scholar.google.com/scholar?q=negative+pressure+wave+leak+localization+pipeline+formula)

### Inferences
- **NPW mini-game.** Put a pressure sensor at each section boundary. On a leak, show two arrival times and let the player compute x = (L + aΔt)/2. This upgrades the answer from "section 3" to "620 m into section 3". Add clock jitter as a difficulty setting. (Formula is [MEMORY]; verify before publishing.)
- **Window trade-off.** Let the player choose the balance window. The vendor table suggests balance takes hours for 3–5% leaks while NPW takes seconds, so a "fast pressure alarm, slow balance confirmation" two-stage flow is realistic.
- **Fault vs. attack signature in the pipeline.** A flow meter sits between two sections. If it lies by δ, one neighbour shows +δ imbalance and the other −δ (a "dipole"). A real leak gives a deficit in one section only. A leak also produces a pressure wave, and a spoofed meter does not. This rule is derived from conservation, not from a cited source.
- **Two-meter collusion.** Spoofing the two meters around one section by matched amounts fakes a clean single-section leak. This is the pipeline version of the a = Hc attack. The pressure sensors break it.
- **Teaching point.** The 12% figure justifies a game message: balance alone misses most real releases, so layer methods.
- **Shut-in case.** Since balance fails at zero flow (API 1130), add a "pipeline shut down" level where only pressure decay reveals the leak.

### Gaps
- The PHMSA final report (December 2012) could not be opened (HTTP 403). The figures above are from the webinar and comments on the draft and have differing denominators.
- The current edition of API RP 1130 was not confirmed. The federal incorporation cites the 2002 second edition, and a listing shows later history entries.
- No peer-reviewed field figures for NPW, acoustic or fiber accuracy were retrieved. The table is one vendor's marketing data.
- Post-2012 PHMSA leak-detection rulemaking was not researched.

## 5. Graph/network-based detection and localization

### Takeaway
Modelling the plant as a graph lets a detector use relationships between neighbouring sensors, and graph neural networks (GNNs) do this by learning. The standard benchmarks are water networks. For 4–8 pipe sections, hand-written conservation residuals per node give the same localization logic without training.

### Cited Findings
- **[V-abs]** BATADAL was a competition on detecting cyberattacks in C-Town, a medium-sized water distribution network run by PLCs and SCADA. Seven teams took part, using data analysis, model-based detection and rule checking. Scoring used time-to-detection and classification accuracy. The test set is 3 months long. Published as Taormina et al., J. Water Resources Planning and Management 144(8), 2018. — [ASCE](https://ascelibrary.com/doi/10.1061/%28ASCE%29WR.1943-5452.0000969); [Water Benchmark Hub](https://waterfutures.github.io/WaterBenchmarkHub/benchmarks/BATADAL.html)
- **[V-abs]** Graph Deviation Network (Deng & Hooi, AAAI 2021) learns the relationship graph between sensors, predicts each sensor from its neighbours with a GNN, and flags deviations. Attention weights indicate which sensors are involved, which helps find the root cause. It was tested on two real sensor datasets with labelled anomalies. — [arXiv 2106.06947](https://arxiv.org/abs/2106.06947)
- **[V-abs]** BattLeDIM 2020 is the leak detection and localization benchmark on the L-Town network. One description gives 782 junctions, 905 pipes and 33 pressure sensors. A 2023 paper reviewed its 18 submissions as baselines. — [Liquor-HGNN, LWDA 2023](https://ceur-ws.org/Vol-3630/LWDA2023-paper40.pdf); [Preprints.org 202610.0666 (not peer-reviewed)](https://www.preprints.org/manuscript/202610.0666)
- **[V-abs]** GNN leak-localization work on BattLeDIM includes Chebyshev graph convolution networks (UCL), algorithm-informed GNNs built on a nominal hydraulic model, and topology-guided GNNs that report larger gains with multiple simultaneous leaks. — [UCL paper](https://discovery.ucl.ac.uk/10155676/1/1-s2.0-S2405896322005882-main.pdf); [arXiv 2408.02797](https://arxiv.org/pdf/2408.02797); [IFIP Networking 2026](https://dl.ifip.org/db/conf/networking/networking2026/1571277940.pdf)
- **[V-abs]** Pasqualetti et al. give graph-theoretic conditions, based on the interconnection structure, for when undetectable attacks exist. — [arXiv 1202.6144](https://arxiv.org/abs/1202.6144)
- **[MEMORY]** Invariant-based detection on the SWaT water treatment testbed (Adepu & Mathur) uses physical rules linking sensors and actuators across stages. The GDN paper's two datasets are, from memory, SWaT and WADI. — [Scholar search](https://scholar.google.com/scholar?q=Adepu+Mathur+distributed+attack+detection+water+treatment+invariants)

### Inferences
- **Node residuals.** Treat the tank and each pipe section as a node. Compute r_i = inflow − outflow − change in stored volume. Localize by which nodes exceed threshold. Classify by pattern: one node means leak, an adjacent +/− pair means a bad or spoofed meter.
- **Sparse sensors make it a puzzle.** L-Town has 33 pressure sensors for 782 junctions, about 1 sensor per 24 junctions. A harder game level could remove some meters so the player must reason over merged sections.
- **Optional "AI detector".** Predict each meter from its two neighbours with linear regression on normal data and flag the largest error. This is the GDN idea at toy scale and runs in a browser.

### Gaps
- No localization accuracy numbers were retrieved for BattLeDIM entries or the GNN papers.
- BATADAL per-team rankings and attack-concealment details were not retrieved.

## 6. Which changes help most? (fault-vs-attack discrimination and localization)

### Takeaway
For **telling faults from attacks**, the strongest additions are a randomized watermark with a correlation test, a third (model-based) level channel with voting, and CUSUM in place of per-sample thresholds. For **localization**, the strongest are per-node conservation residuals with the dipole rule, pressure-wave timing inside a section, and the "more than 2q channels" counting rule.

### Cited Findings
- **[V-full]** Correcting q attacked sensors needs every state direction to be seen by more than 2q sensors. — [Fawzi et al.](https://arxiv.org/pdf/1205.5073)
- **[V-full]** Stateful CUSUM limits stealthy-attack impact better than stateless tests at equal false-alarm rate, and correlated multi-signal models beat per-signal ones. — [Urbina et al.](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- **[V-abs]** Watermarked inputs expose replayed sensor data, at a cost in control performance or delay. — [Mo & Sinopoli 2009 record](https://search.isc.ac/inventory/49/3238687.htm)
- **[V-abs]** CPM/SCADA was the first identifier in about 12% of 197 liquid incidents. — [Kiefner/PHMSA webinar](https://primis-meetings.phmsa.dot.gov/archive/Kiefner_PHMSA_Web_10-05-2012_(1)_PHMSA3.pdf)

### Inferences
- **Suggested build order (effort vs. payoff):**
  1. CUSUM on the existing mass-balance residual.
  2. Random (PRBS) watermark plus sliding correlation test.
  3. Virtual level channel plus 2-out-of-3 vote.
  4. Pipeline dipole rule and pressure-wave timing mini-game.
  5. Edge/central/network detector split.
  6. Optional: neighbour-prediction "AI detector".
- **Decision matrix sketch (our own synthesis, not from a source):**

| What is seen | Watermark response | Hard-wired B vs. model | Network counters | Verdict |
|---|---|---|---|---|
| Mass-balance bias | present | B agrees with A | clean | Leak or process fault |
| A deviates | present on B | B agrees with model | abnormal | Sensor spoof (attack) |
| A deviates | present on B | B agrees with model | clean | Sensor A fault, or stealthy attack |
| Everything looks normal | absent | not applicable | any | Replay attack |
| Feedback ≠ command | present | agree | clean | Actuator fault |
| Feedback ≠ command | present | agree | abnormal | Command injection |

- The third row cannot be resolved by this evidence alone. That is an honest limit to show: a careful attacker who spoofs only A, without touching counters, looks like a sensor fault.

### Gaps
- No source directly ranks these methods against each other for fault-vs-attack discrimination. The ranking is the researcher's judgement.
- Several foundational references remain [MEMORY] only (Liu et al. 2009, Teixeira et al. 2015, Satchidanandan & Kumar 2017, Shoukry, Pajic, SWaT invariants, the NPW formula).
