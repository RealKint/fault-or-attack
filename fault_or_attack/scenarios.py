"""The catalogue of faults and attacks, MITRE ATT&CK technique IDs and recommended responses."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScenarioInfo:
    name: str
    category: str
    what_happens: str
    how_caught: str
    kind: str = "FAULT"           # the truth: "FAULT" or "ATTACK"


FAULTS: dict[str, ScenarioInfo] = {
    "drift": ScenarioInfo(
        "Sensor drift", "Sensor fault",
        "The level sensor slowly reads lower than the real level, so the controller keeps filling.",
        "Compare against a second sensor or an independent high-level switch.",
    ),
    "stuck": ScenarioInfo(
        "Sensor stuck", "Sensor fault",
        "The sensor freezes on its last value, so the pump stays in whatever state it was in.",
        "Flat-line checks, or a backup sensor.",
    ),
    "pump": ScenarioInfo(
        "Pump failure", "Equipment fault",
        "The pump is commanded ON but delivers nothing, so the level drains.",
        "Compare the pump command with flow or motor current.",
    ),
    "valve": ScenarioInfo(
        "Valve stuck open", "Actuator fault",
        "The outlet valve sticks open and drains faster than the pump can refill.",
        "Compare valve command with position feedback or downstream flow.",
    ),
    "leak": ScenarioInfo(
        "Leak", "Process fault",
        "Extra outflow. The controller compensates, so the level looks fine and the fault hides.",
        "Watch pump duty and do a mass balance (more pumping for the same demand).",
    ),
    "power": ScenarioInfo(
        "Power loss", "Utility fault",
        "Pump and sensor go dark and the tank drains downstream with nothing in control.",
        "Power monitoring, backup supply, and fail-safe default positions.",
    ),
}


ATTACKS: dict[str, ScenarioInfo] = {
    "spoof": ScenarioInfo(
        "False data injection", "Cyberattack (sensor data)",
        "A man-in-the-middle rewrites sensor A's messages with believable values just under 40%, "
        "so the controller keeps the pump ON and the tank overflows while the screen looks normal.",
        "Mass balance: the fake level falls while the pump is pumping, and its error jumps around "
        "in a way no physical fault does.",
        kind="ATTACK",
    ),
    "replay": ScenarioInfo(
        "Replay attack", "Cyberattack (compromised trusted device)",
        "A compromised device already on the network records 30 s of healthy readings and plays them "
        "back, fakes the motor feedback, and secretly forces the pump ON (the Stuxnet pattern).",
        "Real sensor noise never repeats, so an exact copy is a recording. The secret pump probes "
        "are also missing from the recording.",
        kind="ATTACK",
    ),
    "smart_replay": ScenarioInfo(
        "Replay + fresh noise", "Cyberattack (smart attacker)",
        "Like the replay attack, but the attacker adds fresh random noise to every replayed reading "
        "so no two seconds ever match exactly.",
        "Exact-copy matching fails. The secret pump probes catch it: the real sensor dips when the "
        "pump pauses, the recording does not (physical watermarking).",
        kind="ATTACK",
    ),
    "stealth": ScenarioInfo(
        "Stealthy spoof", "Cyberattack (smart attacker)",
        "A man-in-the-middle shifts sensor A down by a slowly growing offset that looks exactly like "
        "sensor drift, so the controller overfills the tank.",
        "Physics alone cannot tell it from drift. Fusion catches it: the 'drift' started right after a "
        "never-seen-before device appeared on the control network.",
        kind="ATTACK",
    ),
    "command": ScenarioInfo(
        "Command injection", "Cyberattack (actuator)",
        "An outside computer sends its own write commands to the pump and forces it ON.",
        "Network monitoring sees writes from an unknown host, and the pump runs with no command.",
        kind="ATTACK",
    ),
    "dos": ScenarioInfo(
        "Denial of service", "Cyberattack (network)",
        "A traffic flood drowns the control network, most sensor messages are lost and the "
        "controller flies blind on its last good reading.",
        "Traffic far above normal plus patchy message loss while power is healthy. "
        "A cut cable loses everything and does not raise traffic.",
        kind="ATTACK",
    ),
}


SCENARIOS: dict[str, ScenarioInfo] = {**FAULTS, **ATTACKS}


SMART_ATTACKS = ("smart_replay", "stealth")    # added after the detector was first tuned


REPLAYS = ("replay", "smart_replay")


NEW_DEVICE_ATTACKS = ("spoof", "stealth", "command", "dos")   # attacks that bring a new device onto the network


# MITRE ATT&CK for ICS techniques for each attack culprit (check attack.mitre.org for current IDs).
ATTACK_TECHNIQUES: dict[str, str] = {
    "False data injection": "T0856 Spoof Reporting Message, T0832 Manipulation of View",
    "Replay attack": "T0856 Spoof Reporting Message, T0832 Manipulation of View",
    "Command injection": "T0855 Unauthorized Command Message, T0831 Manipulation of Control",
    "Unauthorised pump control": "T0855 Unauthorized Command Message, T0831 Manipulation of Control",
    "Unauthorised valve control": "T0855 Unauthorized Command Message, T0831 Manipulation of Control",
    "Controller output forged": "T0831 Manipulation of Control, T0821 Modify Controller Tasking",
    "Denial of service": "T0814 Denial of Service, T0829 Loss of View",
    "Disguised attack": "T0856 Spoof Reporting Message (fault-like symptom + new network device)",
}


RESPONSES: dict[str, str] = {
    "FAULT": "Raise a maintenance work order and field-check the equipment named above; keep running only if safe.",
    # The attacker is usually remote, so the response cuts the network path in as well as calling people in.
    "ATTACK": "Put the pump in manual or a safe state, cut the control network off from outside connections "
              "(the attacker may be far away, coming in over the network), keep the logs, and call the "
              "cybersecurity incident team. In Brunei, report it to Cyber Security Brunei through BruCERT "
              "(hotline 245 8001, cert@brucert.org.bn); owners of critical information infrastructure must also "
              "notify the Commissioner of Cybersecurity.",
    "UNKNOWN": "Escalate: have an operator check the real level in the field before deciding.",
}


MODES = ("permanent", "transient", "intermittent")
