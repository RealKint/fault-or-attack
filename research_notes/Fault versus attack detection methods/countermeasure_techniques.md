# Countermeasure techniques for replay, false-data-injection and stealthy attacks (applied to the "Fault or Attack" single-tank simulator)

Scope note: primary papers read in full text were Urbina et al. CCS 2016, Satchidanandan & Kumar (arXiv 1606.08741), Liu/Yan/Mo/Johansson CDC 2018 (online physical watermark design, which restates the Mo & Sinopoli replay model), and Ahmed/Palleti/Mishra (J. Process Control 2022, practical watermarking on the WADI testbed). Other items come from abstracts and search snippets and are marked as such. Simulator mappings are labelled as inferences: they are my engineering suggestions and the papers do not state them.

Simulator recap (from the brief): level L in %, on/off pump (ON below 40%, OFF above 60%), sensor A (noise ±0.3%), optional sensor B, motor feedback, outflow meter, power monitor, packet counts. Current detectors: an exact 8-sample repeat check for replay, and a mass-balance residual with "roughness" (median jump > 0.9%/s) or "falls 3x while pump confirmed filling" checks for FDI. Known hole: a smooth spoof that looks like slow drift is classified as FAULT.

---

## 1. Physical / dynamic watermarking against replay (Mo & Sinopoli 2009; Satchidanandan & Kumar 2016/17), and how to apply it to an on/off pump

### Takeaway
Watermarking adds a secret random signal to the actuator and checks that the sensor "echoes" it through the known plant dynamics. Replayed or simulated sensor data cannot contain the echo of a secret it never saw, so the residual statistics shift. The textbook form assumes a continuous actuator. The one practical deployment paper says outright that bang-bang control is a known limitation. For an on/off pump, the workable versions randomize when the pump switches (random hysteresis thresholds, random dwell, or random short test pulses) and then test whether the level slope follows the secret schedule.

### Cited Findings
**Replay attack model and why a plain chi-square detector fails**
- Replay model: the attacker (1) records sensor data from k1 to k1+Tp, then (2) from time k2 sends y'_k = y_{k-Δk} with Δk = k2-k1. In steady state the replayed data has "exactly the same" statistics as real data, so for many linear systems the two become indistinguishable after a short transient. — [Liu, Yan, Mo, Johansson, "An On-line Design of Physical Watermarks", CDC 2018 (KTH PDF)](https://people.kth.se/~kallej/papers/secure_cdc18liu.pdf)
- Mo & Sinopoli (Allerton 2009, DOI 10.1109/allerton.2009.5394956) analysed an LQG loop with a χ² failure detector. They showed the χ² detector catches replay only when the closed-loop matrix is unstable. For stable systems an authentication signal must be added to the control input, at the price of losing optimal control performance. (Source here is a search summary of later papers, not the original full text.) — [arXiv 2103.00790 (continuous-time watermarking, background section)](https://arxiv.org/pdf/2103.00790); [search summary of Mo & Sinopoli and follow-ups](https://arxiv.org/abs/2209.06267v1)

**Watermark formulation and optimal detector (Liu et al. 2018, building on Mo & Sinopoli)**
- Plant with watermark: x_{k+1} = A x_k + B φ_k + w_k, y_k = C x_k + v_k, with φ_k i.i.d. N(0, U). Without attack, y_k = γ_{k-1} + ϑ_{k-1}, where γ_{k-1} = Σ_t C A^t B φ_{k-1-t} is the known echo of the watermark and ϑ is noise with covariance W = CΣCᵀ + R. — [Liu et al. CDC 2018](https://people.kth.se/~kallej/papers/secure_cdc18liu.pdf)
- Hypotheses: H0 (no attack): y_k ~ N(γ_{k-1}, W). H1 (replay): y_k ~ N(0, 𝒰 + W), where 𝒰 = Σ_τ H_τ U H_τᵀ and H_τ = C A^τ B. Under replay the echo is missing, but the data still carries the old watermark's variance. — [Liu et al. CDC 2018](https://people.kth.se/~kallej/papers/secure_cdc18liu.pdf)
- Neyman–Pearson detector (Theorem 1): reject H0 if g = (y_k − γ_{k−1})ᵀ W⁻¹ (y_k − γ_{k−1}) − y_kᵀ (W + 𝒰)⁻¹ y_k ≥ η, with η set by the desired false-alarm rate. The quantity tr(𝒰 W⁻¹) characterizes detection performance: a larger watermark-to-noise ratio gives better detection. — [Liu et al. CDC 2018](https://people.kth.se/~kallej/papers/secure_cdc18liu.pdf)
- The watermark costs control performance, and later work treats it as an optimization trade-off (Liu et al.) or a co-design with robust/H2 control (Goyal et al. 2022). — [Liu et al. CDC 2018](https://people.kth.se/~kallej/papers/secure_cdc18liu.pdf); [Goyal et al., arXiv 2209.06267](https://arxiv.org/abs/2209.06267v1)

**Dynamic watermarking tests (Satchidanandan & Kumar)**
- Why passive detection fails: if the actuator adds no private excitation, a malicious sensor knows the input exactly. It can report z(t+1) = a z(t) + b g_t(z^t) + w'(t+1) with self-generated noise w' from the right distribution and never look at the real plant. No detector can catch that. — [Satchidanandan & Kumar, arXiv 1606.08741](https://arxiv.org/pdf/1606.08741)
- SISO scheme: x[t+1] = a x[t] + b u[t] + w[t+1], with u[t] = g_t(z^t) + e[t] and e[t] i.i.d. N(0, σ_e²) known only to the actuator. — [arXiv 1606.08741](https://arxiv.org/pdf/1606.08741)
- Test 1: (1/T) Σ (z[k+1] − a z[k] − b g_k(z^k) − b e[k])² → σ_w². With the watermark subtracted, the residual must have only process-noise variance. — [arXiv 1606.08741](https://arxiv.org/pdf/1606.08741)
- Test 2: (1/T) Σ (z[k+1] − a z[k] − b g_k(z^k))² → b²σ_e² + σ_w². Without subtracting it, the watermark's variance must be present. Passing both tests forces the attacker's added distortion to have zero average power. — [arXiv 1606.08741](https://arxiv.org/pdf/1606.08741)
- Finite-time practice: use a moving window of l samples (not the whole history) so that bursty or "sleeper" attackers are not averaged away. Thresholds come from the χ²/Wishart distribution of the windowed sample covariance at false-alarm rate α. The excitation variance σ_e² is chosen from the acceptable detection delay l and the false-alarm rate. SPRT is not directly usable because there is no known attack distribution, so the only decisions are "reject H0" or "keep watching". — [arXiv 1606.08741, Sec. XI](https://arxiv.org/pdf/1606.08741)
- Their example used e[k] ~ N(0,1) with σ_w² = 1, so the watermark variance equalled the process noise. The windowed negative log-likelihood rose steadily after the attack began at epoch 4500. — [arXiv 1606.08741](https://arxiv.org/pdf/1606.08741)
- Related: "Covariance-Robust Dynamic Watermarking" (Aswani et al., arXiv 2003.13908) relaxes the need to know the noise covariance exactly (seen only in search results, not read). — [arXivLens listing](https://arxivlens.com/PaperView/Details/covariance-robust-dynamic-watermarking-7219-2093562)

**Practical watermarking on a real water plant, and the on/off limitation (Ahmed, Palleti, Mishra 2022)**
- Tested on the WADI water distribution testbed (consumer tanks with a modulating valve, flow meter and level switch). The watermark overrides the PID and drives the valve to random openings between 25% and 45%, the range that still meets demand. Each random value is held for a duration d. — [Ahmed et al., J. Process Control 2022](https://strathprints.strath.ac.uk/81324/1/Ahmed_etal_JPC_2022_A_practical_physical_watermarking_approach_to_detect_replay_attacks.pdf)
- Detector: a system model predicts the sensor output from the watermarked input, and residuals are compared with a two-sample Kolmogorov–Smirnov test. D_{n,m} = sup_x |F_n(x) − G_m(x)|, reject if D_{n,m} > c(α)·√((n+m)/(n·m)), with c(α) = √(−½ ln α). — [Ahmed et al. 2022](https://strathprints.strath.ac.uk/81324/1/Ahmed_etal_JPC_2022_A_practical_physical_watermarking_approach_to_detect_replay_attacks.pdf)
- Chunk (window) size: 10 samples gave many false alarms; 120 or more was good; 250 gave the best accuracy/latency trade-off, with 100% TPR on the six consumer tanks. — [Ahmed et al. 2022](https://strathprints.strath.ac.uk/81324/1/Ahmed_etal_JPC_2022_A_practical_physical_watermarking_approach_to_detect_replay_attacks.pdf)
- Stated limitation: watermarking "can not be applied to all types of control, especially in case of a bang-bang control". Overhead: actuator energy scales as E ∝ 1/d, and frequent switching wears components. A long d saves energy but gives the attacker more time to learn the watermark. — [Ahmed et al. 2022](https://strathprints.strath.ac.uk/81324/1/Ahmed_etal_JPC_2022_A_practical_physical_watermarking_approach_to_detect_replay_attacks.pdf)
- For on/off devices, a 2024 paper proposes actuator fingerprinting from transient switching time ("Time Constant") plus active "Control Signal Watermarking", validated on a water treatment testbed (abstract or search snippet only). — [arXiv 2409.16536](https://arxiv.org/html/2409.16536v1)
- Trapiello et al. use a pseudo-random binary {0,1} watermark code that switches at a fixed period, which suggests a binary watermark is feasible (search snippet only). — [IRI-UPC](https://www.iri.upc.edu/download/scidoc/2217)
- Zhang, Keliris, Parisini, Polycarpou use watermarking specifically to tell replay attacks apart from sensor bias faults, which standard detectors confuse (search snippet). — [Zhang et al., L-CSS accepted version](https://arts.units.it/bitstream/11368/2993775/1/Zhang_Keliris_Parisini_Polycarpou_L-CSS_Accepted_Version_4_6_2021.pdf)

### Inferences (implementation design for the simulator; not from sources)
- **Watermark A, random hysteresis thresholds (cheapest).** At each switching event, draw the next ON threshold from U(38, 42)% and the next OFF threshold from U(58, 62)% using a secret seed, i.e. θ_on,j = 40 + δ_j with δ_j ~ U(−2, 2). The real level turns around at the secret thresholds. For a replayed trace (old thresholds) or a synthetic smooth spoof, the reported turning points will not match the current secret draws. Statistic: for each cycle j, e_j = (reported level at commanded switch time) − θ_j. Under H0, e_j ~ N(0, σ_A²) with σ_A ≈ 0.3/√3 ≈ 0.17% if "±0.3%" means uniform noise (check the simulator's noise model). Alarm if Σ e_j²/σ² over the last m cycles exceeds the χ²_m(1−α) quantile, e.g. m = 4 and α = 0.001 gives about 18.5. Cost: about ±2% extra level swing, no extra switching.
- **Watermark B, random switching delay (dwell jitter).** When the controller decides to switch, wait a secret random delay τ_j ~ U(0, 3) s before actually switching. The real level-slope sign change (fill to drain) must happen at t_decision + τ_j. Statistic: estimate the reported slope-change time by fitting a two-segment line on a ±10 s window and compare it to the secret time. Replayed data's kinks will sit at the old times. Correlation form: corr(secret delay sequence, measured kink-time offset) over the last N cycles. With N = 5–8 cycles, the alarm level comes from a permutation test or a t-test on the correlation coefficient.
- **Watermark C, random short test pulses (closest to Satchidanandan-Kumar).** While the pump is OFF and the level sits safely between 45% and 55%, fire a secret random sequence of short pulses, e[k] ∈ {0, 1} Bernoulli(p = 0.1–0.2) with 1–2 s width. Each pulse adds a known level increment ΔL = q_pump·Δt/A_tank. Apply Test 1 and Test 2 to the mass-balance residual r_k = ΔL_meas,k − (ΔL from pump command + e[k] − outflow) over a 60–250 sample window. Test 1: mean of (r_k − b·e_k)² ≈ σ_r². Test 2: mean of r_k² ≈ b²·Var(e) + σ_r². Simpler matched-filter form: S = Σ e_k·ΔL_meas,k / Σ e_k² should be about b, the known per-pulse level rise. Replay or synthetic data gives S ≈ 0. Use a z-test with SE ≈ σ_ΔL/√(Σ e_k²). The pulse size must be clearly larger than noise per pulse window (needs b·√(Σe²) ≫ σ) or the test lacks power. Cost: extra pump starts (motor wear), which matches the E ∝ 1/d trade-off in Ahmed et al.
- All three need the challenge secret kept off the network the attacker controls, for example generated inside the PLC or safety controller. If the attacker owns the controller, the watermark is known (see Section 2).
- A replay that adds fresh noise does not defeat any of these, because fresh noise cannot reproduce the response to the current secret challenge. This fixes the hole in the exact-match detector.

### Gaps
- I could not read the original Mo & Sinopoli 2009 full text. The common sliding-window χ² statistic g_k = Σ_{i=k−T+1}^{k} r_iᵀ P⁻¹ r_i, compared against the χ²_{mT} quantile, comes from general knowledge and should be verified there.
- I found no published watermark design for a hysteresis (bang-bang) level controller. Watermarks A–C above are untested proposals.
- The exact LQG cost-increase formula for the watermark was not extracted.

---

## 2. Authentication (MAC, sequence numbers, timestamps, nonces) and moving-target defense

### Takeaway
Cryptographic message authentication with a freshness element (a sequence number, timestamp or challenge nonce) stops network-level replay and man-in-the-middle tampering cheaply and deterministically. It does nothing if the endpoint that signs the data is compromised: a hacked sensor, PLC or controller signs the lies. Physics-based checks (Sections 1, 3 and 4) are still needed for that case.

### Cited Findings
- DNP3 Secure Authentication v5 uses challenge-response. The challenge carries pseudo-random data, a sequence number and the algorithm, and the response carries an HMAC over the challenge data and the key, plus the sequence number. The standard describes this as a unilateral two-pass mechanism per ISO/IEC 9798-4. — [DNP3 SAv5 (2011) document](https://icscsi.org/library/Documents/ICS_Protocols/DNP3%20Secure%20Authentication%20v5%202011-11-08.pdf)
- An academic analysis of SAv5 notes that all sub-protocols use sequence numbers and freshly generated challenge data to prevent replay. — [Search summary, J. Computer Security 2018 (JCS-181139)](https://https-sage-cnpereading-com-443.webvpn1.xju.edu.cn/doi/10.3233/JCS-181139)
- SAv5 provides authentication and integrity, not confidentiality, and its main purpose is protecting critical state-changing commands. — [Trout Software, Securing DNP3 (vendor blog)](https://www.trout.software/resources/securing-dnp3)
- Vendor documentation describes appending a sequence number plus an HMAC to each message as a replay-protection pattern. — [Schneider Electric Geo SCADA DNP3 HMAC help](https://tprojects.schneider-electric.com/geoscadahelp/geo%20scada%202020/content/DNP3DriverGuide/HMAC.htm)
- Urbina et al. observed that 95% of traffic in a real large US water facility was Modbus, with 108 devices and 106 slave PLCs. Classic Modbus has no authentication, which is the default environment these attacks exploit. — [Urbina et al., CCS 2016](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)

### Inferences
- **Simulator implementation:** each sensor frame becomes (sensor_id, seq, t_send, value, tag) with tag = HMAC-SHA256(key_sensor, sensor_id‖seq‖t_send‖value), truncated to 8–16 bytes. Python's built-in `hmac` and `hashlib` are enough. The receiver rejects a frame if the tag fails, if seq ≤ last_seq (replay or reorder), or if |t_recv − t_send| > a skew bound (for example 2 sample periods).
  - A naive replay of recorded frames fails immediately because the sequence numbers are stale.
  - A replay attacker without the key cannot forge new tags.
  - This yields a clean "ATTACK" signature (an authentication failure), which faults almost never produce. A real fault yields a missing frame or a value anomaly, not a bad MAC.
- **Challenge-nonce variant:** the controller sends a random nonce n_k, and the sensor must return HMAC(key, n_k‖value). This proves freshness without synchronized clocks.
- **Limits worth showing in the demo:** (a) a compromised sensor firmware or PLC holds the key and signs false values; (b) an attacker upstream of signing (physical tampering with the transducer, or spoofing the measured phenomenon) is untouched; (c) key management, latency and legacy-device support are real costs. That is why the demo should pair MAC/sequence checks with physics checks.
- **Moving-target defense** (rotating keys, randomized polling schedules, randomized register maps or ports, randomized watermark seeds) raises attacker learning cost. The random watermark seeds and the random polling times in Section 1 are moving-target ideas in practice. I found no specific moving-target paper with implementable parameters for this setting.
- **Network-level replay telltales without crypto** (useful because the simulator already counts packets): inter-arrival time jitter changes, duplicate or out-of-order sequence or transaction IDs (Modbus/TCP has a transaction identifier field), an extra MITM hop changing TTL or latency, and packet-count anomalies on the sensor link. These are heuristics and weak against a careful attacker.

### Gaps
- Modbus/TCP Security (TLS) specifics were not retrieved.
- No source found with numeric moving-target parameters for ICS.

---

## 3. CUSUM and χ² bad-data detection against stealthy and slow attacks; why they are evaded; attacker-impact bounds (Urbina et al. 2016)

### Takeaway
A stateless test (alarm if |r_k| > τ) lets a stealthy attacker shift the reading by up to τ every step. A stateful CUSUM caps the persistent bias the attacker can hide to δ per step once the statistic is pinned at the threshold. That bias still accumulates if the predictor is re-anchored on the spoofed measurement, which is exactly the "slow drift" spoof. The fix is to use CUSUM on an open-loop physical prediction that cannot be dragged along, plus independent channels.

### Cited Findings
- Residual r_k = y_k − ŷ_k from a physical model, either an LDS (x_{k+1} = A x_k + B u_k + ε_k, y_k = C x_k + e_k) or an AR model. Stateless test: alarm if |r_k| ≥ τ. — [Urbina et al., CCS 2016](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- Non-parametric CUSUM: S_0 = 0, S_{k+1} = max(0, S_k + |r_k| − δ). Choose δ so that E[|r_k| − δ] < 0 under no attack. Alarm when S_k > τ, then reset S to 0. — [Urbina et al. 2016](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- Optimal greedy stealthy attack:
  - Against the stateless test: y^a_{k+1} = ŷ_{k+1} ± τ.
  - Against CUSUM: y^a_{k+1} = ŷ_{k+1} ± (τ + δ − S_k). Once S_k = τ, it is y^a_{k+1} = ŷ_{k+1} ± δ at every later step.
  - So with CUSUM, once the attacker reaches the threshold, "the attack no longer has enough room", and raising τ further makes no difference.
  - — [Urbina et al. 2016](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- Proposed metric: maximum undetected deviation Δ (y-axis) versus expected time between false alarms E[T_fa] ≈ T_E / n_FA from attack-free runs (x-axis), instead of the false-alarm rate. For CUSUM, S_k must be simulated with resets to count false alarms. — [Urbina et al. 2016](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- Water-tank testbed (first-principles LDS model): δ = 0.002 was chosen so that S_k stays near 0 without attack, with T_E = 8 h of attack-free data. They ran 20 undetected attacks of about 40 min each. With stateless detection, large spills happen unless τ is tiny, which brings many false alarms. With CUSUM, overflow (Δ > 0.3 m) requires a large threshold. A threshold with E[T_fa] = 170 min avoided spilling. — [Urbina et al. 2016](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- LDS models were about an order of magnitude better than AR models at limiting stealthy impact, and stateful beat stateless except for very small τ < δ. Models that capture correlation between multiple signals limit impact more than one AR model per signal. — [Urbina et al. 2016](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- PI control limits undetected actuator attacks better than P control, because the integral action creates a compensation that the LDS model expects. — [Urbina et al. 2016](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- Stealthy attacks that keep residuals under the χ² threshold still leave non-random sign patterns in the residuals. The memoryless Cumulative Sign (CUSIGN) detector tracks the occurrence of residual signs against what randomness predicts, and is paired with CUSUM for magnitude bounds (Bonczek & Bezzo, IFAC 2020; abstract only, exact statistic not retrieved). — [arXiv 2005.07821](https://arxiv.org/abs/2005.07821)
- A related "model-based randomness monitor" for stealthy sensor attacks exists from the same group (title only seen). — [arXiv 2005.07832](https://arxiv.org/pdf/2005.07832)
- Giraldo et al. 2018 (ACM Computing Surveys 51(4):76) is the canonical survey of physics-based attack detection. It uses a taxonomy of detection, location and validation, preceded by NIST GCR 16-010 (model, trust model, detection mechanism, evaluation metrics). — [NIST CSRC listing](https://csrc.nist.gov/pubs/journal/2018/07/a-survey-of-physicsbased-attack-detection-in-cps/final); [NIST GCR 16-010](https://nvlpubs.nist.gov/nistpubs/gcr/2016/NIST.GCR.16-010.pdf)

### Inferences (simulator mapping)
- **Why the current detector is fooled:** the mass-balance residual is one-step (ΔL_meas − ΔL_expected). A smooth spoof that adds a bias of about b %/s per step has a small, non-rough residual each step. That is the stateless-test regime, and the attacker gets b per step for free.
- **Fix 1, CUSUM on the one-step mass-balance residual with signed (two-sided) accumulation:**
  - S⁺_k = max(0, S⁺_{k−1} + r_k − δ), and S⁻_k = max(0, S⁻_{k−1} − r_k − δ).
  - Set δ to about 0.5× the largest drift rate you consider plausible for genuine noise (half the minimum shift to detect, the classic Page rule; general knowledge, not from the sources above).
  - Calibrate τ from attack-free simulation runs so that E[T_fa] is, say, more than 10× the demo duration. Urbina et al. calibrated from 8 h of normal data.
  - The signed version matters: |r_k| as in Urbina et al. inflates under pure noise, while a signed CUSUM targets a persistent one-direction bias, which is what a drift spoof is.
- **Fix 2, open-loop integrated mass balance (an "anchor" the spoof cannot drag):**
  - Integrate L_model(t) = L(t0) + ∫(q_in(pump feedback) − q_out(meter))/A dt from a trusted anchor point. Anchors are re-zeroed only at independent events: the high-level switch trip, sensor B agreement, or a known start.
  - Track D(t) = L_A(t) − L_model(t). Integrator error from meter noise grows like σ√t, while a spoof grows like b·t, so test D(t)/√t or apply CUSUM on D.
  - This directly bounds the cumulative slow-drift advantage that Urbina's analysis gives a CUSUM-pinned attacker against a re-anchored predictor.
- **Fix 3, CUSIGN-style runs test on residual signs:**
  - Under no attack, sign(r_k) is roughly Bernoulli(0.5) and independent.
  - Count n⁺ over a window N = 60 and alarm if |n⁺ − N/2| > z·√N/2 (z = 3.3 for about 0.1% two-sided).
  - Alternatively, use the Wald–Wolfowitz runs test on the number of sign runs. A biased smooth spoof shows too many same-sign residuals and too few runs.
  - The exact CUSIGN formula in Bonczek & Bezzo was not retrieved, so this is a standard-statistics stand-in.
- **Fix 4, a χ² variance check on the residual** (the "too smooth" test): fresh-noise-free synthetic spoofs often have residual variance below σ², while real sensors keep σ² ≈ (0.17%)². A two-sided χ² test on (N−1)s²/σ² over N = 60 catches spoofs that are too clean.

### Gaps
- No source gave a closed-form bound on cumulative level error for an integrating (tank) process under CUSUM-pinned attacks. The b·t accumulation argument is my inference.
- The exact CUSIGN statistic and thresholds were not retrieved.

---

## 4. Telling a slow stealthy spoof from genuine sensor drift

### Takeaway
No single published test separates "drift fault" from "drift-shaped attack". The literature consensus is cross-checking against independent redundant channels plus temporal and behavioural signatures, and researchers note the fault-versus-attack distinction is under-explored. The strongest practical discriminators for this simulator:
- the physical outcome that independent channels reveal (pump energy, runtime, outflow, high/low switches, sensor B);
- whether the deviation is goal-directed relative to the control thresholds;
- whether the deviation obeys drift physics.

### Cited Findings
- Stealthy attackers who know the model and noise can stay within fault-detector thresholds. — [Bonczek & Bezzo, arXiv 2005.07821](https://arxiv.org/pdf/2005.07821)
- Park et al. (TCPS 2017) use redundant sensors measuring the same variable as intervals and detect via pairwise inconsistencies. They note that most methods treat attacks and transient faults the same way, and they model faults separately. — [Park et al. 2017 TCPS (PDF)](https://www.seas.upenn.edu/~weimerj/pdf/2017-TCPS-SensorFusion.pdf); [UPenn repository](https://repository.upenn.edu/cis_papers/844)
- Zhang/Keliris/Parisini/Polycarpou: replay attacks and sensor bias faults produce different detector time responses. Standard fault isolation does not exploit this, and watermarking can separate them (search snippet). — [Zhang et al. EJC accepted version](https://arts.units.it/bitstream/11368/2993773/1/Zhang_Keliris_Parisini_Polycarpou_EJC_Accepted_25_Jun_2021.pdf)
- An NP-CUSUM chapter describes online diagnostics that distinguish cyber attacks from component failures such as sensor bias, drift and freezing (search snippet; details not read). — [Springer 10.1007/978-3-319-95597-1_9](https://link.springer.com/10.1007/978-3-319-95597-1_9)
- "On Distinguishability of Anomalies as Physical Faults or Actuation Cyberattacks" (arXiv 2311.09342) treats fault-versus-attack distinguishability formally (title and snippet only). A 2023 survey notes that distinguishing the two remains under-explored. — [arXiv 2311.09342](https://arxiv.org/pdf/2311.09342)
- Rationale: physical maintenance fixes faults but does not remediate attacks, so the distinction drives the response. — [Search summary citing par.nsf.gov 10499417](https://par.nsf.gov/servlets/purl/10499417)

### Inferences (concrete discriminators for the simulator; each scored as evidence, not a hard rule)
1. **Drift physics (fault prior).** Real drift is usually monotonic, slow (bounded rate, e.g. |dD/dt| < 0.01–0.05 %/min in a toy model; pick a value and state it as an assumption), unrelated to the control cycle, and continuous across pump ON/OFF transitions. Flag ATTACK evidence when:
   - the bias rate changes at pump switch events;
   - the bias reverses direction;
   - the bias is piecewise (starts or stops abruptly in slope);
   - the bias rate exceeds the physical bound.
   If the simulator models temperature, a real drift term can be made temperature-correlated (for example d = k_T·(T − T0)), and a spoof without that correlation is suspicious.
2. **Independent-channel consistency (strongest).** Compare L_A against:
   - sensor B;
   - the integrated mass balance (Section 3, Fix 2);
   - the pump power monitor (energy ∝ pumped volume if the head is constant), so cumulative pumped volume from kWh should match the level rise;
   - the high/low level switch trip times.

   A fault in A shows up only in A and leaves the physical outcome normal: no overflow trend, normal pump duty. An attack that spoofs A low makes the pump run longer, so pump runtime, energy and the integrated inflow rise while A claims the level is low. Physical-outcome divergence (overflow risk or real level from the mass balance going past 60%) is therefore strong ATTACK evidence.
3. **Goal-directedness ("who benefits").** Compute where the spoof pushes the controller: does D(t) make the controller hold the pump ON past the real 60% (overflow attack) or OFF below the real 40% (dry-run attack)? Score the projected real level excursion beyond the safe band under the spoofed control. A drift fault is direction-random relative to the hazard. A spoof consistently increases hazard and is often timed or shaped around the 40/60 thresholds, for example a reading that hovers just below 60% so the pump never shuts off. A feature: the fraction of time the reported level sits within ±1% of a switching threshold, compared with its baseline.
4. **Sensor-noise fingerprint.** A real drifting sensor keeps its noise spectrum, variance and quantization. A spoof often changes them, either too smooth or with noise that is too white or the wrong distribution. Use the χ² variance test and lag-1 autocorrelation of the high-pass residual (Section 3, Fix 4).
5. **Watermark response (Section 1).** A drifting but honest sensor still echoes the secret pump challenges, offset by the bias. A spoof or replay does not, or echoes them wrongly. This is the cleanest separator: fault means the echo is present plus an offset, while attack means the echo is missing or mismatched.
6. **Cyber-side corroboration.** Packet-count, sequence or MAC anomalies on the sensor link at the same time push toward ATTACK, and their absence is weak evidence for FAULT (a compromised endpoint produces none).

### Gaps
- No published numeric bounds on "typical drift rate" for level transmitters were found in this pass, so any rate threshold is a modelling choice.
- No formal paper found that implements a "goal-directedness" score. That idea is an inference.

---

## 5. Replay detection beyond exact match

### Takeaway
A replay with fresh noise added defeats exact matching. More robust replay tests are (a) the active-challenge mismatch (watermark: strongest), (b) cryptographic freshness (sequence number or MAC), and (c) statistical similarity to stored history in the de-noised trend domain, combined with a mismatch against current independent channels.

### Cited Findings
- In steady state, replayed data has the same statistics as live data, so purely statistical detectors without excitation struggle. This is the motivation for watermarking. — [Liu et al. CDC 2018](https://people.kth.se/~kallej/papers/secure_cdc18liu.pdf)
- K-S test on model residuals with a watermarked input detected replay with 100% TPR at a 250-sample chunk on WADI. — [Ahmed et al. 2022](https://strathprints.strath.ac.uk/81324/1/Ahmed_etal_JPC_2022_A_practical_physical_watermarking_approach_to_detect_replay_attacks.pdf)
- Sequence numbers and fresh challenge data are the protocol-level defense in DNP3 SAv5. — [DNP3 SAv5](https://icscsi.org/library/Documents/ICS_Protocols/DNP3%20Secure%20Authentication%20v5%202011-11-08.pdf)

### Inferences (implementable tests)
- **Trend-domain similarity search.** Keep a ring buffer of past readings. Smooth with a moving average (window w = 5–10) or fit per-window linear slopes, then compute the max normalized cross-correlation between the latest window (N = 30–60 samples) and every past window. A replay with fresh noise added still gives ρ > 0.95 on the smoothed trend, especially on the sawtooth cycle shape. The catch: an on/off loop is naturally periodic, so live cycles also correlate highly. The test therefore has to compare the details, such as cycle period, phase and the exact turning levels, against the current pump feedback and timing. That is why the watermark-randomized turning points (Watermark A/B) make replay obvious: past cycles had different random thresholds.
- **Actuator-consistency mismatch (no watermark needed).** Replayed sensor data is decoupled from current actuation. Check that the slope sign of L_A matches the current pump feedback (ON means rising unless outflow > inflow) and the current outflow meter. Natural variation in outflow demand makes old data mismatch. Your existing mass-balance residual already does part of this. Add a correlation test between d L_A/dt and (q_pump − q_out)/A over N = 60 samples: expected ρ ≈ 1 when live, and near zero or negative under replay.
- **Noise-statistics tests.** Replays with re-added noise double the noise (old plus new) unless the attacker de-noises first. Compare the high-pass residual variance with the baseline using an F-test or χ² test, and compare spectral flatness or lag-1 autocorrelation.
- **Timing and sequence anomalies.** Repeated or non-monotonic sequence or transaction IDs, timestamp jumps, changed inter-arrival jitter, or packet-count increases on the link (an injection channel).

### Gaps
- No paper found that benchmarks trend-correlation replay detection on hysteresis-controlled loops. The approach above is untested.

---

## 6. Multi-asset / spatial correlation: faults are local and random, attacks coordinated

### Takeaway
The literature supports using multi-sensor agreement and spatial or temporal correlation: a real fault usually appears in one sensor, while a real physical event appears in all correlated sensors. Coordinated attacks that keep spoofed sensors mutually consistent are the hard case, and work on that is relatively sparse. Formal results exist mostly as Park et al.'s redundancy-based detection and Urbina's finding that multi-signal correlated models limit impact.

### Cited Findings
- Most FDIA detection work assumes independent false data per compromised sensor. Coordinated (collusive) attacks modify adjacent sensors so their readings stay spatially and temporally consistent, and few works address detecting them in WSNs. — [MDPI Sensors 23(13):5943](https://mdpi.com/1424-8220/23/13/5943)
- Sensor-measurement-based methods detect simple FDIAs but not stealthy ones. A 2024 framework groups sensors by cross-correlation, fits ARIMA per group to learn temporal cross-correlation, and applies a consistency criterion to flag abnormal nodes. — [Sensors 24(5):1643 (PMC)](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10935136/)
- A patent describes the rule: a fault seen at one sensor but not at nearby sensors suggests spoofing, while an actual fault on a component is detected by multiple sensors. — [US Patent 10372569](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/10372569)
- Correlated multi-signal physical models limit stealthy-attack impact more than per-signal AR models. — [Urbina et al. 2016](https://users.soe.ucsc.edu/~alacarde/papers/ccs16.pdf)
- Pairwise inconsistency among redundant sensors used for attack-resilient fusion. — [Park et al. TCPS 2017](https://www.seas.upenn.edu/~weimerj/pdf/2017-TCPS-SensorFusion.pdf)

### Inferences
- **Single-tank use:** treat {A, B, mass balance, pump energy, switches} as a "spatial" set. The decision table:
  - A disagrees with everything else: FAULT if the deviation looks like drift physics, ATTACK if it is goal-directed or fails the watermark.
  - A and B agree but both disagree with the mass balance and energy: likely a coordinated attack (two independent sensors faulting identically is improbable), or a mass-balance channel fault. Check the switches.
  - Everything agrees: normal or a physical event.
- **Multi-tank extension:** under independent faults, anomaly onsets across assets are roughly Poisson and uncorrelated in time. Coordinated attacks produce near-simultaneous onsets or the same signature (same bias shape or rate) across assets. A simple test: count assets whose CUSUM fired within a window W (e.g. 60 s) and compare with a binomial or Poisson expectation from the per-asset fault rate p. P(k ≥ 2 in W) ≈ C(n,2)(pW)² should be tiny, so k ≥ 2 suggests coordination. This is my inference and I found no source with this exact test.

### Gaps
- I found no formal paper giving a hypothesis test specifically for "temporal coincidence across assets means attack" in ICS. The suggestions above are standard probability reasoning, not cited methods.
- Spatially consistent coordinated spoofing remains an acknowledged open problem in the cited WSN literature.
