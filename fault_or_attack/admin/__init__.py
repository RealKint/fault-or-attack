"""The admin console: a control-room screen that runs the detector live and turns its verdicts into incidents.

    python "FAULT OR ATTACK.py" --admin                      # simulated plant with a lab panel for drills
    python "FAULT OR ATTACK.py" --admin --realistic          # the PI-valve plant
    python "FAULT OR ATTACK.py" --admin --replay-csv FILE    # recorded plant data instead of the simulator

Then open http://127.0.0.1:8800 in a browser. Standard library only.
"""
