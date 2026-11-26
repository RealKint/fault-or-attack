"""Turns the detector's second-by-second verdicts into incidents an operator can acknowledge and close.

The detector may give the same verdict every second for minutes. The control room wants one incident for it,
not hundreds of alarms, so verdicts with the same answer and the same culprit update one open incident.
Every change is written to an audit log (one JSON object per line) so the shift can be reviewed afterwards.
"""

from __future__ import annotations

import csv
import io
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from ..detector import Verdict


# Most urgent first. The console's headline shows the most urgent incident the detector still sees.
SEVERITY = {"ATTACK": 5, "PHYSICAL": 4, "FAULT": 3, "UNKNOWN": 2, "IT": 1}

# Which part of docs/Brunei OT Incident Playbook.md each answer leads to (the table in the README).
PLAYBOOK = {
    "FAULT": "Section 1: maintenance as normal",
    "ATTACK": "Sections 1, 2 and 4: safe state, isolate or shut down, report to BruCERT",
    "IT": "Sections 1 and 2: keep running, cut the IT-OT link",
    "PHYSICAL": "Section 4: site security; SHENA and the Petroleum Authority for safety or spill incidents",
    "UNKNOWN": "Section 1: field-check the real level within 15 minutes, then escalate",
}

OUTCOMES = ("Confirmed attack", "Confirmed fault", "Confirmed physical incident", "Planned work",
            "False alarm", "Other")


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class Incident:
    id: int
    label: str
    culprit: str
    reason: str
    mitre: str
    action: str
    playbook: str
    first_tick: int
    last_tick: int
    opened: str                     # wall-clock time
    status: str = "new"             # new -> acknowledged -> resolved
    active: bool = True             # the detector still sees it (no verdict for clear_after seconds = not active)
    seconds_seen: int = 1
    owner: str = ""
    outcome: str = ""
    secondary: bool = False         # raised as a second finding beside another verdict
    drill: str = ""                 # lab drill running when it opened (filled in when the drill is revealed)
    run: int = 0                    # which plant run it belongs to (goes up each time the plant is restarted)
    confidence: str = ""            # latest confidence: High, Medium or Low
    evidence: list[str] = field(default_factory=list)    # latest families of evidence that agree
    conflicts: list[str] = field(default_factory=list)   # latest families pointing elsewhere
    also_seen: list[str] = field(default_factory=list)   # other culprits the detector named for the same problem
    history: list[dict] = field(default_factory=list)

    @property
    def severity(self) -> int:
        return SEVERITY.get(self.label, 0)


class IncidentLog:
    def __init__(self, log_dir: Path | None = None, clear_after: int = 30):
        self.clear_after = clear_after
        self.items: list[Incident] = []
        self.next_id = 1
        self.run = 0                    # current plant run; only its incidents can take new verdicts
        self.version = 0               # bumps on every change, so the page knows when to redraw the list
        self.lock = threading.RLock()
        self.log_path = None
        if log_dir is not None:
            log_dir.mkdir(parents=True, exist_ok=True)
            self.log_path = log_dir / f"incidents-{datetime.now():%Y%m%d-%H%M%S}.jsonl"

    # --- audit log -----------------------------------------------------------
    def _audit(self, event: str, inc: Incident, **extra) -> None:
        self.version += 1
        if self.log_path is None:
            return
        line = {"time": now(), "event": event, "incident": inc.id, "label": inc.label, "culprit": inc.culprit,
                **extra}
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(line) + "\n")
        except OSError:
            pass   # a full disk must not stop the console

    def _note(self, inc: Incident, who: str, what: str, note: str = "") -> None:
        inc.history.append({"time": now(), "who": who, "what": what, "note": note})

    # --- from the detector -----------------------------------------------------
    def observe(self, verdict: Verdict | None, tick: int) -> list[Incident]:
        """Feed one second's verdict. Returns incidents opened this second (for the page's alarm sound)."""
        opened = []
        with self.lock:
            if verdict is not None:
                for v, secondary in ((verdict, False), (verdict.also, True)):
                    if v is None:
                        continue
                    inc = self._match(v)
                    if inc is None:
                        opened.append(self._open(v, tick, secondary))
                    else:
                        self._update(inc, v, tick)
            for inc in self.items:
                if inc.active and tick - inc.last_tick > self.clear_after:
                    inc.active = False
                    if inc.status != "resolved":
                        self._note(inc, "detector", f"No longer seen for {self.clear_after} s")
                        self._audit("cleared", inc, tick=tick)
                    else:
                        self.version += 1
        return opened

    def _match(self, v: Verdict) -> Incident | None:
        """The incident this verdict belongs to. A resolved incident the detector has not stopped seeing still
        counts, so closing an incident does not make a new one pop up the very next second; once the detector has
        been quiet on it for clear_after seconds, a recurrence opens a new incident. Incidents from before a plant
        restart never match: the detector that raised them is gone."""
        current = [i for i in self.items if i.run == self.run]
        for inc in reversed(current):
            if inc.label == v.label and inc.culprit == v.culprit and (inc.status != "resolved" or inc.active):
                return inc
        live = [i for i in current if i.status != "resolved" and i.active and not i.secondary]
        # One problem, one incident: while an incident is open and still seen, the detector's other names for the
        # same answer (an attack first called "false data injection", then "disguised attack") join it.
        same = [i for i in live if i.label == v.label]
        if same:
            return same[-1]
        # An early warning (UNKNOWN) while a firm answer is already open is part of that incident.
        if v.label == "UNKNOWN":
            firm = [i for i in live if i.label != "UNKNOWN"]
            if firm:
                return max(firm, key=lambda i: i.severity)
        return None

    def _open(self, v: Verdict, tick: int, secondary: bool) -> Incident:
        inc = Incident(id=self.next_id, label=v.label, culprit=v.culprit, reason=v.reason, mitre=v.mitre,
                       action=v.action, playbook=PLAYBOOK.get(v.label, ""), first_tick=tick, last_tick=tick,
                       opened=now(), secondary=secondary, run=self.run, confidence=v.confidence,
                       evidence=list(v.evidence), conflicts=list(v.conflicts))
        self.next_id += 1
        self._note(inc, "detector", f"Opened: {v.label} - {v.culprit}" + (" (second finding)" if secondary else ""),
                   v.reason)
        # A firm answer explains the early warnings (UNKNOWN) still open, so they are closed into it. A more serious
        # answer is linked from the milder incidents it may explain, e.g. a "leak" FAULT that turns out to be a
        # disguised attack; those stay open for the operator to close.
        if not secondary and v.label != "UNKNOWN":
            for other in self.items:
                if other.status == "resolved" or not other.active:
                    continue
                if other.label == "UNKNOWN":
                    other.status, other.outcome = "resolved", f"Explained by #{inc.id}"
                    self._note(other, "detector", f"Closed: explained by #{inc.id} {inc.label} - {inc.culprit}")
                    self._audit("superseded", other, by=inc.id)
                elif other.severity < inc.severity:
                    self._note(other, "detector", f"Now also: #{inc.id} {inc.label} - {inc.culprit}")
        self.items.append(inc)
        self._audit("opened", inc, tick=tick, reason=v.reason, mitre=v.mitre, secondary=secondary)
        return inc

    def _update(self, inc: Incident, v: Verdict, tick: int) -> None:
        if tick != inc.last_tick:
            inc.seconds_seen += 1
        inc.last_tick = tick
        if inc.status == "resolved":
            return
        if v.label != inc.label:
            return                     # an early warning folded into a firm incident: keep the firm evidence
        if (v.confidence, v.evidence, v.conflicts) != (inc.confidence, inc.evidence, inc.conflicts):
            if v.confidence != inc.confidence:
                self._note(inc, "detector", f"Confidence: {v.confidence or '-'}", "; ".join(v.evidence))
            inc.confidence, inc.evidence, inc.conflicts = v.confidence, list(v.evidence), list(v.conflicts)
            self.version += 1
        if v.culprit != inc.culprit and v.culprit not in inc.also_seen:
            inc.also_seen.append(v.culprit)
            self._note(inc, "detector", f"Also seen: {v.culprit}", v.reason)
            self._audit("also seen", inc, tick=tick, culprit2=v.culprit, reason=v.reason)
            return
        if not inc.active:
            inc.active = True
            self._note(inc, "detector", "Seen again", v.reason)
            self._audit("seen again", inc, tick=tick)
        if v.reason != inc.reason:
            inc.reason = v.reason      # the latest evidence; quiet change, no audit line every second
            self.version += 1

    def plant_restarted(self, tick: int) -> None:
        """The plant and the detector have just been restarted, so the new detector has seen none of the open
        incidents. Start a new run and mark the old incidents as no longer seen; otherwise a new problem with the same
        answer (a second ATTACK) would be filed into an old incident instead of opening its own. Open incidents stay
        open for the operator to close."""
        with self.lock:
            self.run += 1
            for inc in self.items:
                if inc.active:
                    inc.active = False
                    if inc.status != "resolved":
                        self._note(inc, "detector", "Plant restarted: no longer being watched")
                        self._audit("cleared", inc, tick=tick, why="plant restarted")
                    else:
                        self.version += 1

    # --- from the operator -------------------------------------------------------
    def get(self, inc_id: int) -> Incident:
        for inc in self.items:
            if inc.id == inc_id:
                return inc
        raise KeyError(f"No incident #{inc_id}")

    def acknowledge(self, inc_id: int, who: str, note: str = "") -> Incident:
        with self.lock:
            inc = self.get(inc_id)
            if inc.status == "resolved":
                raise ValueError(f"Incident #{inc_id} is already resolved")
            inc.status, inc.owner = "acknowledged", who
            self._note(inc, who, "Acknowledged", note)
            self._audit("acknowledged", inc, who=who, note=note)
            return inc

    def resolve(self, inc_id: int, who: str, outcome: str, note: str = "") -> Incident:
        with self.lock:
            inc = self.get(inc_id)
            if outcome not in OUTCOMES:
                raise ValueError(f"Outcome must be one of {OUTCOMES}")
            if inc.status == "resolved":
                raise ValueError(f"Incident #{inc_id} is already resolved")
            if inc.label == "ATTACK" and outcome != "Confirmed attack" and not note.strip():
                raise ValueError("Closing an ATTACK as anything else needs a note saying how it was ruled out")
            inc.status, inc.outcome = "resolved", outcome
            inc.owner = inc.owner or who
            self._note(inc, who, f"Resolved: {outcome}", note)
            self._audit("resolved", inc, who=who, outcome=outcome, note=note)
            return inc

    def add_note(self, inc_id: int, who: str, note: str) -> Incident:
        with self.lock:
            inc = self.get(inc_id)
            if not note.strip():
                raise ValueError("The note is empty")
            self._note(inc, who, "Note", note)
            self._audit("note", inc, who=who, note=note)
            return inc

    def tag_drill(self, since_tick: int, text: str) -> None:
        with self.lock:
            for inc in self.items:
                if inc.last_tick >= since_tick and not inc.drill:
                    inc.drill = text
            self.version += 1

    # --- views -------------------------------------------------------------------
    def headline(self) -> Incident | None:
        """The most urgent incident the detector still sees and nobody has closed."""
        live = [i for i in self.items if i.active and i.status != "resolved"]
        return max(live, key=lambda i: (i.severity, i.last_tick), default=None)

    def as_list(self, limit: int = 200) -> list[dict]:
        with self.lock:
            order = sorted(self.items, key=lambda i: (i.status == "resolved", -i.severity * (i.active and i.status
                                                                                            != "resolved"), -i.id))
            out = []
            for inc in order[:limit]:
                d = asdict(inc)
                d["severity"] = inc.severity
                out.append(d)
            return out

    def counts(self) -> dict:
        with self.lock:
            return {"open": sum(i.status != "resolved" for i in self.items),
                    "new": sum(i.status == "new" for i in self.items),
                    "total": len(self.items)}

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "answer", "culprit", "confidence", "evidence", "opened", "first_second", "last_second",
                    "seconds_seen", "status", "owner", "outcome", "mitre", "drill", "reason", "history"])
        with self.lock:
            for i in self.items:
                hist = " | ".join(f"{h['time']} {h['who']}: {h['what']}" + (f" ({h['note']})" if h['note'] else "")
                                  for h in i.history)
                w.writerow([i.id, i.label, i.culprit, i.confidence, " | ".join(i.evidence), i.opened,i.first_tick, i.last_tick, i.seconds_seen, i.status,
                            i.owner, i.outcome, i.mitre, i.drill, i.reason, hist])
        return buf.getvalue()
