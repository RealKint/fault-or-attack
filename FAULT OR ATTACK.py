"""
FAULT OR ATTACK.py - Tank level control loop with injectable industrial faults AND cyberattacks,
plus a detector that decides whether each abnormal event is a FAULT or an ATTACK.

Hibiscus LEAP 2026 fit
----------------------
    Downstream Oil & Gas - Safety and Operational Reliability
    ICT                  - Cybersecurity and Resilience

The plant is a tank that is filled by a pump and drained by downstream demand.
A simple controller reads a level sensor and switches the pump:
    sensor below 40%  -> pump ON
    sensor above 60%  -> pump OFF
Healthy behaviour: the level wobbles around 50% and the pump runs about 50% of the time.

When the level goes wrong, an operator has to answer one question fast:
is equipment failing (call maintenance) or is someone attacking the plant (call security)?
The detector answers it with one idea:

    Faults obey physics. Attacks have to fake it.

A broken part still follows the laws of the tank: a leak loses water at a steady rate,
an ageing sensor drifts slowly, a dead pump stops. An attacker who wants to cause damage
without being seen has to forge data, and forged data leaves fingerprints: readings that
repeat exactly, a sensor that falls while the pump is pumping, a pump that starts by itself,
commands from a computer that is not the controller, or a flood of network traffic.

Ideas borrowed from published work (see reports/Fault versus attack detection methods.md):
    - CUSUM on the mass-balance error, for early warning of slow, steady losses (Urbina et al., CCS 2016)
    - Active probing / physical watermarking: the controller pauses the pump at secret moments and
      checks sensor A dips, which a recording cannot do (after Mo & Sinopoli 2009)
    - Cyber-physical fusion: a fault-like symptom right after a new network device = attack
    - MITRE ATT&CK for ICS technique IDs and a recommended response on every verdict
    - Fair evaluation: baselines, a confusion matrix, long healthy runs, and smart attackers
      (fresh-noise replay, drift-mimicking spoof) added after the detector was first tuned
Known limit: an insider who fakes a smooth drift from an already-trusted device leaves no
network trace, and physics alone cannot tell that from real sensor drift.

Realistic mode (--realistic), shaped by the real HAI testbed data:
    - PI-controlled supply valve with lag, readings rounded to 0.1 %, slowly wandering sensor noise
    - Control-law consistency: the detector replays the controller's own PI law (dual detector,
      Xue et al. 2025) - the check that worked best on real HAI data
    - Valve tracking: a valve moving away from its command is being driven by someone else
    - Active challenge: before blaming equipment, the detector ASKS the controller for a probe and
      only says FAULT once sensor A has visibly echoed it
    - Level-vs-valve correlation: a live sensor follows the valve even with a leak or drift;
      a recording cannot (judged only while the plant itself is steady)
    - Thresholds for natural repeats, freezes and correlation are learned from healthy runs only

Usage examples
--------------
    python "FAULT OR ATTACK.py" --all                     # every fault and attack, with and without a backup sensor
    python "FAULT OR ATTACK.py" --all --save grid.png     # same, plus a picture
    python "FAULT OR ATTACK.py" --fault leak              # run one fault, show the detector's verdict
    python "FAULT OR ATTACK.py" --attack replay           # run one attack, show the detector's verdict
    python "FAULT OR ATTACK.py" --fault drift --backup    # drift, but with a second (healthy) level sensor
    python "FAULT OR ATTACK.py" --attack spoof --plot     # show a window with graphs (needs matplotlib)
    python "FAULT OR ATTACK.py" --eval 20                 # accuracy over 20 random seeds and every duration mode
    python "FAULT OR ATTACK.py" --attack replay --live    # animated demo: watch the detector decide (needs matplotlib)
    python "FAULT OR ATTACK.py" --mystery                 # live demo of a random, hidden scenario: fault or attack?
    python "FAULT OR ATTACK.py" --attack spoof --live --save demo.gif   # record the demo for slides
    python "FAULT OR ATTACK.py" --all --realistic         # plant closer to the real HAI testbed
    python "FAULT OR ATTACK.py" --dashboard               # one-page accuracy dashboard (accuracy_dashboard.png)
    python "FAULT OR ATTACK.py" --web                     # record every demo for the website (web/index.html)
    python "FAULT OR ATTACK.py" --hai                     # validate on REAL data (HAI 22.04, test day 1)
    python "FAULT OR ATTACK.py" --hai data/hai/test2.csv  # ... and test day 2
    python "FAULT OR ATTACK.py" --fault power --mode transient --save power.png

Only the standard library is needed for the simulation and the detector.
matplotlib is needed only for --plot and --save.

Project files (press Run on this one; it starts the menu)
---------------------------------------------------------
    FAULT OR ATTACK.py   this starter: shows the menu, or runs the command-line options
    fault_or_attack/     the program itself, one file per part:
        config.py            settings, and the realistic-plant preset
        scenarios.py         the faults and attacks, MITRE ATT&CK IDs, recommended responses
        plant.py             the simulated tank plant and its controller
        detector.py          the FAULT-or-ATTACK detector
        learning.py          thresholds learned from healthy runs (cached in learned_thresholds.json)
        evaluation.py        single-run report, results table and accuracy scoring
        plots.py             graphs, the overview grid and the accuracy dashboard
        live_demo.py         the animated live demo and mystery mode
        hai_validation.py    checks on real plant data (HAI dataset)
        web_export.py        records every demonstration for the website (web/)
        cli.py               command-line options and the interactive menu
    tests/               automated tests: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys

from fault_or_attack.cli import main, menu

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        menu()
