"""The three scripted demonstrations shown on stage: an equipment fault, a cyberattack, and an attack disguised as
a fault. Each one is an ordinary lab drill with a fixed scenario, a short lead-in of normal running, and words for
the audience. tests/test_admin_console.py checks that every demo still gets the answer and confidence it promises.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Demo:
    id: str
    title: str
    scenario: str          # key in scenarios.KNOWN_SCENARIOS
    kind: str              # the right answer: FAULT or ATTACK
    story: str             # what is happening, in one sentence for the audience
    watch: str             # what to point at on the screen
    lead: int = 15         # seconds of normal running before it starts, so the audience sees a healthy tank first
    mode: str = "permanent"

    def as_dict(self) -> dict:
        return asdict(self)


DEMOS: tuple[Demo, ...] = (
    Demo("fault", "Equipment fault", "leak", "FAULT",
         "A pipe starts leaking. Worn equipment: nobody is to blame.",
         "FAULT, Low confidence at first, then Medium as the leak holds steady. Only the physics checks "
         "see it, and nothing happens on the network. Send a technician."),
    Demo("attack", "Cyberattack", "command", "ATTACK",
         "A computer that is not the controller sends its own commands and forces the pump on.",
         "ATTACK at once. It reaches High confidence when two kinds of evidence agree: the network log shows writes "
         "from an unknown host, and the pump runs with no command from the controller. Call the incident team."),
    Demo("tricky", "Looks like a fault, is an attack", "stealth", "ATTACK",
         "An attacker shifts the level reading slowly, exactly the way an ageing sensor drifts.",
         "On physics alone this is 'sensor drift'. The console says ATTACK, High confidence: the 'drift' began "
         "right after a never-seen-before device joined the control network. Worn parts do not bring laptops."),
)

BY_ID = {d.id: d for d in DEMOS}
