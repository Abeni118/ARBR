"""
Writes normalized Detection records to the shared database for
Member 2's Risk Engine to consume.

Uses a plain 'detections' table. Swap out _get_connection() if the team
lands on a different DB engine than what's in .env.example.
"""
import json
import logging

from . import config
from .schema import Detection

log = logging.getLogger("detector.sink")

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS detections (
    detection_id      VARCHAR(36) PRIMARY KEY,
    timestamp         DATETIME NOT NULL,
    agent_id          VARCHAR(64),
    agent_name        VARCHAR(255),
    host              VARCHAR(255),
    detection_type    VARCHAR(64) NOT NULL,
    severity          VARCHAR(16) NOT NULL,
    evidence          JSON,
    raw_alert_id      VARCHAR(64),
    wazuh_rule_id     VARCHAR(16),
    wazuh_rule_level  INT,
    risk_score        FLOAT DEFAULT NULL,
    processed         BOOLEAN DEFAULT FALSE
);
"""

INSERT_SQL = """
INSERT INTO detections
    (detection_id, timestamp, agent_id, agent_name, host,
     detection_type, severity, evidence, raw_alert_id,
     wazuh_rule_id, wazuh_rule_level)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


class DetectionSink:
    """
    Writes detections to MySQL/MariaDB if a connector is available;
    otherwise falls back to appending JSON lines to a local file so
    development/testing isn't blocked on DB setup.
    """

    def __init__(self, fallback_path: str = "detections.jsonl"):
        self.fallback_path = fallback_path
        self._conn = None
        self._try_connect()

    def _try_connect(self):
        try:
            import mysql.connector  # pip install mysql-connector-python
            self._conn = mysql.connector.connect(
                host=config.DB_HOST,
                user=config.DB_USER,
                password=config.DB_PASSWORD,
                database=config.DB_NAME,
            )
            cur = self._conn.cursor()
            cur.execute(CREATE_TABLE_SQL)
            self._conn.commit()
            cur.close()
            log.info("Connected to %s@%s/%s for detection sink",
                      config.DB_USER, config.DB_HOST, config.DB_NAME)
        except Exception as e:  # noqa: BLE001 - broad on purpose for dev fallback
            log.warning("DB connection unavailable (%s); falling back to %s",
                        e, self.fallback_path)
            self._conn = None

    def write(self, detection: Detection) -> None:
        if self._conn is not None:
            self._write_db(detection)
        else:
            self._write_fallback(detection)

    def _write_db(self, d: Detection) -> None:
        cur = self._conn.cursor()
        cur.execute(INSERT_SQL, (
            d.detection_id, d.timestamp, d.agent_id, d.agent_name, d.host,
            d.detection_type, d.severity, json.dumps(d.evidence),
            d.raw_alert_id, d.wazuh_rule_id, d.wazuh_rule_level,
        ))
        self._conn.commit()
        cur.close()

    def _write_fallback(self, d: Detection) -> None:
        with open(self.fallback_path, "a") as f:
            f.write(json.dumps(d.to_dict()) + "\n")
