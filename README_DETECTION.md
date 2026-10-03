# Wazuh & Detection Module

Member 1's piece of the attack-resistant backup/recovery pipeline:
**Monitor → Detect** (feeds into Member 2's Risk Engine).

## What's here

```
rules/
  local_rules.xml     Custom Wazuh correlation rules (ransomware patterns)
detector/
  config.py           Settings (env-var driven, matches project .env.example)
  analysis.py         Entropy check, extension/pattern matching, mass-change tracker
  schema.py           Detection record format - the handoff contract to Risk Engine
  processor.py        Turns one raw Wazuh alert into 0+ Detection records
  sink.py              Writes Detections to the shared DB (falls back to local
                       JSON lines if DB isn't reachable yet - keeps dev unblocked)
  main.py              Entrypoint: --tail (live) or --replay (testing)
sample_alerts.jsonl    Sample alert stream for testing without a live pipeline
requirements.txt
```

## Detection logic

Two layers, working together:

1. **Wazuh-side (`local_rules.xml`)** - XML correlation rules that run
   inside the manager itself:
   - `100101` - mass file-change burst (15+ events / 20s) from one agent
   - `100102` - suspicious file extension (`.locked`, `.encrypted`, etc.)
   - `100103` - ransom-note-style filename (`README_DECRYPT.txt`, etc.)
   - `100104` - composite: mass-change + bad extension together = highest confidence
   - `100105` - shadow copy / backup deletion command (Windows, needs Sysmon/command logging)

2. **Python-side (`detector/`)** - consumes the resulting alert JSON and
   applies heuristics that are awkward to express in Wazuh XML:
   - Its own sliding-window mass-change tracker (independent confirmation)
   - Shannon entropy sampling on changed files (encrypted data ≈ random,
     entropy trends toward 8.0 bits/byte)
   - Normalizes everything into one `Detection` record shape (see `schema.py`)
     and writes it to the shared DB for the Risk Engine to score/prioritize

## Installing the Wazuh rules

```bash
docker cp rules/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

## Running the detector

```bash
pip install -r requirements.txt --break-system-packages

# Test against sample data (no live Wazuh needed):
python3 -m detector.main --replay sample_alerts.jsonl

# Follow a live alerts.json (run on/near the manager):
python3 -m detector.main --tail --alerts-path /var/ossec/logs/alerts/alerts.json
```

Set DB connection via environment variables (matches `.env.example` at
the repo root): `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`. Without
a reachable DB, detections are appended to `detections.jsonl` locally
so development isn't blocked.

## Known gap / next steps

- Local Docker test environment couldn't get FIM alerts to fire reliably
  when tested directly against the manager container's own filesystem
  (likely an inotify/overlay-fs quirk specific to that setup). The rules
  and detector logic are built and tested against realistic sample alert
  JSON (`sample_alerts.jsonl`) matching Wazuh's real schema instead.
- To fully validate end-to-end: deploy a real Wazuh **agent** (not just
  the manager) on a test host/VM, enable FIM there, and confirm alerts
  flow through to `--tail` mode.
- Handoff schema (`schema.py`) should be reviewed with Member 2 before
  being treated as final - flag any fields the Risk Engine needs that
  aren't here yet.
