# Brunei OT Incident Playbook

Snapshot of 24 November 2026. The working copy is a Claude Doc; re-export this file after changing it there.

One page for a Brunei oil and gas control room: when a strange reading becomes a cyber incident, whether to isolate or keep running, how to restore safely, and who to tell. It is the next-step roadmap for Fault or Attack (Hibiscus LEAP 2026, Day 5).

## 1. Escalation criteria

Any one of these starts a cyber investigation, not just a maintenance job. Dragos found 82% of organisations have no such rule, and 30% of its incidents began as plant problems nobody could explain.

| Trigger | Who acts | Within |
| --- | --- | --- |
| Detector says **ATTACK** (any confidence) | Operator puts the process in a safe state; calls the incident team (CIRT) | Immediately |
| Detector says **UNKNOWN**, or a fault nobody can explain | Field-check the real level with an independent gauge; escalate to CIRT if still unexplained | 15 minutes |
| A FAULT verdict soon after a new device, foreign write, or office IT incident | Treat as ATTACK until ruled out | Immediately |
| Detector says **IT** (office IT hit, plant checks all normal) | Keep running; cut the IT–OT link and keep watching (see section 2). Any later FAULT counts as ATTACK | Within 1 minute of the IT alert |
| Alarm silenced, setpoint or controller program changed without a work order | CIRT | Immediately |
| Detector heartbeat stops | Operator runs on independent gauges; CIRT checks the detector | Immediately |
| Urgent call or email asking to change a setting, open remote access or move money | Confirm by callback on a known number before acting | Before acting |

A FAULT verdict with a clear cause goes to maintenance as normal.

## 2. Isolate or keep running

Safety first: the overfill trip and safety system act on their own and are never switched off to keep production going. Then decide with this table. Colonial Pipeline stopped in about 15 minutes but took about 5 days to restart, so stop only what the evidence requires.

| Situation | Decision |
| --- | --- |
| Office IT hit; detector says plant physics normal; OT shows no new devices or foreign writes | **Keep running.** Cut the IT–OT link at the data diode or firewall and watch closely |
| ATTACK verdict on the plant, but hard-wired gauges and manual control work | **Isolate the control network from outside** and run critical parts by hand (manual switch) |
| Readings can't be trusted and the plant can't run safely by hand | **Controlled shutdown** by the site's normal procedure |
| A safety function is affected (alarm silenced, safety system changed) | **Shut down** that unit and call CIRT |

Authority: the shift supervisor can order a stop without waiting for anyone; the CIRT lead decides when to isolate or reconnect. Before switching anything off, keep the evidence: network logs, historian data and, where possible, a memory image.

Keep a written **security emergency plan** for deliberate attacks, by network or on site, alongside the normal emergency plan. Norway requires one by law (Petroleum Act section 9-3), and it is a useful model for Brunei sites.

## 3. Restoration order

Recovery is an engineering check, not "wipe and reinstall": one named person signs off each step, following the site's normal start-up procedure.

1. Agree the safe state and keep it while you work.
2. Network and security equipment: firewalls, data diode, switches.
3. Servers that host OT software, and OT user accounts (reset passwords).
4. Engineering PC and operator screens, rebuilt from clean images.
5. Controller programs and settings, checked against signed backups; alarm limits and interlocks verified.
6. Detector and historian, with the detector's learned baseline re-checked.
7. The link to office IT (scheduling, billing), last.
8. Lessons learned within two weeks; update the response plan (Code of Practice 7.1.4).

**Practise once a year (our recommendation).** Run a yearly exercise of this playbook with at least two set objectives, for example "decide isolate or run within 15 minutes" and "restore one controller from a signed backup".

## 4. Who to report to in Brunei

A cyber incident is an act "without lawful authority" (Cybersecurity Act, Cap. 272, s2), so a genuine equipment fault needs no cyber report, but an attack does.

**Report once.** Write one incident record, then send the same facts to every body below that applies, so reports never disagree.

| Who | When | How |
| --- | --- | --- |
| **BruCERT** (Cyber Security Brunei) | Any confirmed or suspected cyberattack | Hotline 245 8001 · cert@brucert.org.bn · online incident form at brucert.org.bn |
| **Commissioner of Cybersecurity** | Owners of designated critical information infrastructure (energy is an essential service), for prescribed incidents on it or any connected system | Within the "prescribed period" (not yet published); failing to report: up to B$100,000 and/or 2 years (Act s16) |
| **SHENA and the Petroleum Authority** | Anyone hurt, or a safety or environmental incident | Their reporting channels; check current forms and deadlines |
| **The Director named in the 2008 Regulations** | Oil reaching the sea | Prevention of Pollution of the Sea (Reporting of Pollution Incidents) Regulations 2008 |
| **Petroleum Authority (asset integrity)** | A safety-critical equipment deviation, such as the overfill trip bypassed or failed | Close it out by its deadline and report asset integrity status at the agreed frequency (Directive No. 01/2021) |
| **SHENA (major hazards)** | A loss of containment or major-hazard event at a site with a safety case | Follow the safety case under the WSH (Control of Major Accident Hazards) Regulations, and its reporting procedure |

Open question: the exact deadline under s16 is set by regulation and was not found in any public document.

## Sources

- Brunei [Cybersecurity Order, 2023](https://aipalync.org/document/view/1813), now the Cybersecurity Act, Chapter 272 (Revised Edition 2024): s2 definitions, s16 reporting
- Cyber Security Brunei, Code of Practice for Critical Information Infrastructure v2.0 (September 2026): clauses 6.1, 6.2, 7.1, 10.2–10.4
- [BruCERT incident reporting](https://www.brucert.org.bn/form/incident-reporting)
- [Dragos 2026 OT Year in Review](https://www.dragos.com/blog/dragos-2026-ot-cybersecurity-year-in-review): escalation gap, incident origins
- [Colonial Pipeline CEO testimony, June 2021](https://www.hsgac.senate.gov/imo/media/doc/Testimony-Blount-2021-06-08.pdf): stop and restart times
- [SANS: closing the remediation gap](https://www.sans.org/blog/dont-just-detect-restore-closing-remediation-gap): restoration as engineering verification
- [Brunei pollution incident regulations, 2008](https://lpr.adb.org/sites/default/files/resource/%5Bnid%5D/bru91358.pdf)
- [Petroleum Authority Directive No. 01/2021, Asset Integrity Management of Oil and Gas Facilities](https://www.pa.gov.bn/wp-content/uploads/2025/12/UP-Directive-No.-012021-Asset-Integrity-Management-of-Oil-and-Gas-Facilities.pdf)
- Brunei [Workplace Safety and Health Order, 2009](https://lpr.adb.org/sites/default/files/resource/%5Bnid%5D/brunei-darussalam-workplace-safety-and-health-order-2009-english.pdf) and its Control of Major Accident Hazards Regulations (2013, 2017)
- Havtil (Norwegian Ocean Industry Authority), *Safety and Responsibility: Understanding the Norwegian Regime* (2024): safety versus security, Petroleum Act section 9-3
- [Independent Review of the Security of Critical Infrastructure Act 2018, final report](https://www.homeaffairs.gov.au) (Australia, February 2026): report once, all-hazards; [White & Case summary](https://www.whitecase.com/insight-alert/review-soci-act) (July 2026)
