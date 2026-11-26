# Hibiscus LEAP 2026 Hackathon

## Goal
Win the Hibiscus LEAP 2026 hackathon (Hibiscus Petroleum x Brunei Innovation Lab).
Theme: **safety for oil and gas critical infrastructure**.

## Our entry
- Problem statement: **ICT: Cybersecurity and Resilience** — "How might we strengthen our
  cybersecurity posture and build resilient digital operations?" (also touches Downstream
  Oil & Gas safety and operational reliability).
- Team of 2–3 HND Software Engineering students in Brunei.
- Core idea: help operators tell a **fault** (send a technician) apart from a **cyberattack**
  (call the cybersecurity team and report to BruCERT) in an oil storage tank's control system.
  Motto: *faults obey physics, attacks have to fake it.*
- GitHub repo: `RealKint/fault-or-attack` (public). The website in `web/` is published to
  GitHub Pages by `.github/workflows/pages.yml`: realkint.github.io/fault-or-attack

## Project layout
- `FAULT OR ATTACK.py` — starter script: menu and command-line options (calls `fault_or_attack.cli`).
- `fault_or_attack/` — the program:
  - `plant.py` — tank simulator (pump, outlet valve, level sensor A, optional backup sensor);
    simple on/off mode and `--realistic` mode with a PI-controlled valve shaped by HAI data.
  - `scenarios.py` — catalogue of 6 faults (`drift`, `stuck`, `pump`, `valve`, `leak`, `power`),
    6 attacks (`spoof`, `replay`, `smart_replay`, `stealth`, `command`, `dos`), a stress
    attack (`forge`), physical-side events (corrosion, water ingress, wall thinning, theft,
    tampering, drone, planned work...) and office-IT cases (`it_hit`, `it_spread`, `it_fault`).
    `KNOWN_SCENARIOS` holds them all. MITRE ATT&CK for ICS IDs and recommended responses
    included. Each runs `permanent`, `transient` or `intermittent`.
  - `admin/` — the control-room console (`--admin`, http://127.0.0.1:8800): live plant,
    NORMAL/FAULT/ATTACK/PHYSICAL/IT/UNKNOWN banner, incidents with ack/notes/resolve,
    audit log in `admin_logs/` (git-ignored), CSV playback, lab panel for drills.
    Standard library only. Shows High/Medium/Low confidence with the evidence behind it.
    `admin/demos.py` holds the 3 one-click stage demos (fault = `leak`, attack = `command`,
    tricky = `stealth`); a test checks each still shows what its button text promises, so
    change the words and the test together.
  - `detector.py` — the FAULT/ATTACK decision: mass balance, CUSUM, active probing,
    control-law consistency, network checks.
  - `learning.py` — learns thresholds from healthy runs only (`learned_thresholds.json`).
  - `evaluation.py` — accuracy, confusion matrix, false-alarm runs (`--eval`, `--dashboard`).
  - `hai_validation.py` — check against the real HAI 22.04 testbed dataset (`--hai`).
  - `live_demo.py`, `plots.py` — animated demo and graphs (need matplotlib).
  - `web_export.py` — writes `web/data.js` (`--web`).
  - `cli.py` — argument parsing and menu.
- `tests/` — `test_fault_or_attack.py`; expected outputs in `tests/golden/`; the first
  simulator kept for comparison in `tests/reference/original_simulator.py`.
- `web/` — static website (story, two games, results, topology map). `index_v1_backup.html`
  is an old copy and is git-ignored.
- `reports/`, `research_notes/` — research reports and saved evaluation runs.
- `data/hai/` — HAI dataset (~150 MB), git-ignored; download it yourself (see README).
- Demo media in the root: `demo*.gif`, `accuracy_dashboard.png`, `fault_or_attack_grid.png`,
  `mind_map.svg`, `topology_map.svg`.
- Not in this repo: the old `fault_sim.py` / `fault_sim_gui.py` (Tkinter window). The
  package above replaced the simulator; the GUI, if still wanted, lives elsewhere on my laptop.

## Commands
```bash
python "FAULT OR ATTACK.py"                   # menu
python "FAULT OR ATTACK.py" --all             # every fault and attack
python "FAULT OR ATTACK.py" --attack replay   # one attack and the verdict
python "FAULT OR ATTACK.py" --mystery         # live demo of a hidden scenario
python "FAULT OR ATTACK.py" --eval 20         # accuracy over 20 seeds
python "FAULT OR ATTACK.py" --admin           # control-room console in the browser
python "FAULT OR ATTACK.py" --web             # regenerate web/data.js
python -m unittest discover -s tests          # tests (HAI test skips without the data)
python -m http.server 8765 --directory web    # serve the website locally
```
The simulator and detector use only the standard library (Python 3.10+);
matplotlib (`requirements.txt`) is only for plots, GIFs and the live demo.

## Results
- The README's Results table and Known limits are the single source of truth; don't copy
  numbers here. Never quote a number in a pitch that hasn't been re-run on current code.
- If detector logic changes, re-run the evaluations and tests, then update the README,
  `accuracy_dashboard.png` and `web/data.js` together.
- Evaluations score only the detector's FIRST firm answer. Also test what it says later
  in a run and in back-to-back console drills: that is how two bugs hid (fixed 26 Nov 2026:
  incidents surviving a plant restart, and fusion forgetting the new device after 120 s).
- Confidence (High/Medium/Low) counts independent evidence families (Physics, Hard-wired,
  Network, Control) in `detector.py` `_grade`; it never changes an answer (tested). A family
  counts only when one of its own checks fires. Measured 26 Nov 2026 (main 12 scenarios, both
  plants, 10 seeds): High right 14,803/14,803 seconds shown; Medium 96.8%; Low 93.1%.
- Sensor B tampering (fixed 26 Nov 2026): a tamper switch with no work order makes the
  detector stop trusting sensor B (`_b()`) and counts as unplanned site access. Site fusion,
  like network fusion, judges by when the problem BEGAN (`episode_start`), so it no longer
  forgets the visit after `access_window`. `tamper_b` now stays PHYSICAL for a whole 30-min run.
  Trade-off: an insider helping a network forger who leaves no network trace is shown as
  PHYSICAL (on-site tampering), not ATTACK.

## Reference material
- `docs/Hibiscus X BIL - LEAP 2026 Problem Statements.pdf` — official problem statements.
  Check it before suggesting features so ideas stay inside the chosen statement.
- `docs/WhatsApp Image 2026-11-05 at 7.02.52 PM.jpeg` — event information.
- Those two organiser files are git-ignored by name (public repo): they exist only on this
  laptop, teammates need their own copy, never commit them.
- `docs/Brunei OT Incident Playbook.md` — our own playbook, linked from each detector
  answer; this one IS committed.

## How to work with me
- I'm a student: explain changes step by step and say why, not just what.
- Keep the demo runnable offline on a laptop (no access to a live plant).
- Judges include an oil and gas company: frame features around plant safety and
  operator decisions.
