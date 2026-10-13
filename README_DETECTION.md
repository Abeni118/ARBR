# Wazuh & Detection Module

Member 1's piece of the attack-resistant backup/recovery pipeline:
**Monitor -> Detect**, feeding the backend API (dashboard, risk, decision).

## What's here

```
rules/local_rules.xml     Custom Wazuh correlation rules (ransomware patterns)
detector/
  config.py               Settings (env-var driven)
  analysis.py             Entropy check, extension/pattern matching, mass-change tracker
  schema.py               Detection record format
  processor.py            Turns one raw Wazuh alert into 0+ Detection records
  converter.py            Detection -> backend SecurityEvent payload
  api_sink.py             POSTs events to the backend API (used with --sink api)
  sink.py                 Writes Detections to a MySQL `detections` table, or detections.jsonl
  main.py                 Entrypoint: --tail (live) or --replay (testing), --sink db|api
sample_alerts.jsonl       Sample alert stream for testing without a live pipeline
tests/test_detector_api.py  Unit tests for the converter and API sink (no network needed)
```

## Detection logic

1. **Wazuh side (`rules/local_rules.xml`)** - correlation rules that run in the manager:
   - `100101` mass file-change burst (15+ events in 20s from one agent)
   - `100102` suspicious extension (`.locked`, `.encrypted`, ...)
   - `100103` ransom-note-style filename
   - `100104` composite: mass-change + bad extension (highest confidence)
   - `100105` shadow-copy / backup deletion command (Windows; needs Sysmon or command logging)
2. **Python side (`detector/`)** - consumes the alert JSON and adds checks that are awkward in XML:
   a sliding-window mass-change tracker, Shannon entropy sampling of changed files
   (encrypted data approaches 8 bits/byte), extension and ransom-note matching.

## How it connects to the rest of the system

Detections are sent to the backend as security events:

```
Wazuh alerts.json -> detector (processor) -> converter -> POST /api/internal/security-events
```

| API field (`SecurityEventCreate`) | Comes from |
|---|---|
| `source` | `DETECTOR_SOURCE` (default `wazuh-detector`) |
| `source_event_id` | `<wazuh alert id>:<detection_type>` - deterministic, so replaying the same alert is reported as a duplicate (HTTP 200) instead of creating a second event |
| `occurred_at` | detection timestamp |
| `event_type` | detection type (`suspicious_extension`, `ransom_note`, `mass_file_modification`, ...) |
| `event_severity` | `low` / `medium` / `high` / `critical` |
| `summary`, `indicators`, `evidence` | built from the detection (file path, counts, Wazuh rule/alert ids) |
| `asset_id` **or** `asset_external_ref` | exactly one: `DETECTOR_ASSET_ID` if set, otherwise `{external_source: "wazuh", external_id: <agent name>}` |

Delivery rules (see `api_sink.py`): `201` created, `200` duplicate. Rejections (`4xx`: unknown
asset, validation, bad token) and outages (`5xx`, unreachable) are logged and the detection is
appended to `detections_unsent.jsonl`, so nothing is lost. With no token configured nothing is
sent at all.

### Setup

1. **Backend: create a component token** with the `security_events:write` scope and start the
   API with it (generate the value; never commit it):
   ```bash
   TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
   export MVP_COMPONENT_TOKENS='[{"component_id":"wazuh-detector","token":"'"$TOKEN"'","scopes":["security_events:write"]}]'
   cd backend && python3 -m uvicorn app.main:app --port 8000
   ```
2. **Register the monitored host as an asset** in the backend. The API never creates assets
   implicitly. Either note its UUID and set `DETECTOR_ASSET_ID`, or register it with
   `external_source` = `wazuh` and `external_id` = the Wazuh agent name (e.g. `test-endpoint`).
3. **Run the detector** with the same token:
   ```bash
   export DETECTOR_API_URL=http://127.0.0.1:8000
   export DETECTOR_API_TOKEN="$TOKEN"
   # export DETECTOR_ASSET_ID=<asset uuid>      # optional, see above
   python3 -m detector.main --replay sample_alerts.jsonl --sink api
   python3 -m detector.main --tail --alerts-path /var/ossec/logs/alerts/alerts.json --sink api
   ```

Environment variables: `DETECTOR_API_URL`, `DETECTOR_API_TOKEN`, `DETECTOR_SOURCE`,
`DETECTOR_ASSET_ID`, `DETECTOR_ASSET_EXTERNAL_SOURCE`, `DETECTOR_API_TIMEOUT_SECONDS`.

## Installing the Wazuh rules

```bash
docker cp rules/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

## Testing

```bash
python3 -m pytest tests/test_detector_api.py -q     # converter + API sink, no network
python3 -m detector.main --replay sample_alerts.jsonl                # default sink (DB or detections.jsonl)
```

## Known limitations

- **Live Wazuh pipeline not validated end to end.** In the local Docker setup, FIM alerts did not
  fire when monitoring the manager container's own filesystem. The rules and detector were tested
  against sample alert JSON that follows Wazuh's alert schema. Next step: deploy a real Wazuh
  agent on a test host and confirm alerts reach `--tail`.
- **Entropy sampling reads the file locally**, so it only works where the detector can open the
  changed file (on the endpoint, not on a manager that only sees alert metadata).
- **The backend rejects secret-like field names and values** in `summary`, `indicators` and
  `evidence`. The detector sends none, but a file path containing a credential-looking string
  could be rejected; such events are kept in `detections_unsent.jsonl`.
- The `Detection` fields in `schema.py` are mapped one way (Detection -> SecurityEvent). If the
  risk or decision components need more detail, add it to `evidence` in `converter.py`.
