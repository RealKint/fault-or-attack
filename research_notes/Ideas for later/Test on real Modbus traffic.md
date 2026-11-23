# Idea for later: test the detector on real Modbus traffic

*Saved 23 November 2026. Not started. Source: the "Defending Oil and Gas Plants, Shift by Shift" research report (free OT toolkit section), plus a discussion of how to apply it here.*

## Why
Apart from the HAI check, every result comes from this project's own simulator, so a judge can ask whether we are grading our own homework. Running the detector on a plant we did not build, over a real industrial protocol, answers that. It also fits the LEAP Day 3 deliverable (working demo, risk register) and the Day 4 test log.

## Option 1 (do first): wrap our own tank simulator in real Modbus
- Run the tank simulator as a Modbus device (Python library pymodbus).
- Let OpenPLC (free software PLC) run the pump logic.
- Attack it with real Modbus tools, inside our own lab only.
- Capture the traffic with Malcolm (CISA / Idaho National Laboratory; bundles Zeek, the ICSNPP Modbus parser and Suricata).
- The physics stay the same, so the detector works unchanged, and the network side becomes real.
- Estimated effort: 3 to 5 days.

## Option 2 (later): port to GRFICSv2
- A free practice plant on five virtual machines: process simulation (a pressurised chemical reactor, not a storage tank), OpenPLC, ScadaBR operator screen in a DMZ, pfSense firewall, engineering workstation. All talk Modbus.
- Needs a new mass balance for the reactor's feeds, outflows, level and pressure.
- Estimated effort: 1 to 2 weeks. Needs a laptop with about 16 GB RAM. Several forks exist (original by Fortiphyd; the report cites rmashadi/GRFICSv2); check the details before relying on them.

## How the detector connects
- Route A (process values): read values over Modbus (read-only) or from the HMI's records, and convert them into the detector's Record format. A new adapter module next to `fault_or_attack/hai_validation.py`.
- Route B (network evidence): from Malcolm / Zeek ICSNPP logs, fill the fields the detector already uses: writes from unknown hosts -> `unknown_writes`, never-seen devices -> `new_devices`, packets per second -> `packets`.

## What to test
- Attacks: setpoint change from the engineering workstation; man-in-the-middle fake readings; PLC logic upload; Modbus writes from an unexpected machine.
- Faults (add to the simulation code): frozen sensor, drifting sensor, stuck valve, leak.
- Score: attacks caught, how early, and false alarms over hours of normal running (the Carnegie Mellon lesson: never a single accuracy number).

## Plan
| Step | Work | Time |
|---|---|---|
| 1 | Modbus-wrap the tank, connect OpenPLC | 2-3 days |
| 2 | Record healthy hours, learn thresholds | 1 day |
| 3 | Run 3-4 real Modbus attacks plus faults, capture with Malcolm | 1-2 days |
| 4 | Score and write up | 1 day |
| Later | GRFICSv2 port | 1-2 weeks |

## Limits
- Still a simulation, just not ours. HAI stays the only real-plant evidence.
- Faults must be injected by us.
- Attacks only inside our own lab: never against real equipment or other people's networks.

## Who does what
The lab (virtual machines) runs on a laptop; the code (Modbus wrapper, adapter, attack and fault scripts, scoring) can be written in a Claude Code session.
