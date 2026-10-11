"""
decision_logger.py - Keeps an audit trail of every Decision.

Why this exists:
    After an incident, people will ask "what did the engine decide, when,
    and why?". This file records the answer to that question.

How it works:
    1. Each Decision is converted into a plain dictionary (JSON-friendly).
    2. It is stored in memory in a list, for quick lookups.
    3. It is also appended as ONE LINE to a log file (JSON Lines format:
       one JSON object per line). We only ever ADD lines, never edit or
       delete them, which is what you want from an audit log.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Decision


# Python's built-in logging system. Messages sent here appear in the
# console/terminal when the application is running.
console_logger = logging.getLogger(__name__)

# Default location of the audit file (relative to where you run the app).
DEFAULT_LOG_FILE = "logs/decision_audit.jsonl"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _json_default(value: Any) -> str:
    """Tell json.dumps how to handle types it doesn't understand.

    JSON has no date type, so datetimes become ISO text such as
    "2026-09-28T10:15:30+00:00". Anything else unusual becomes a string
    so logging never crashes because of odd data in `raw_data`.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def decision_to_dict(decision: Decision) -> Dict[str, Any]:
    """Convert a Decision (and everything inside it) into a plain dict.

    dataclasses.asdict() walks through nested dataclasses for us, so the
    events and the risk assessment are converted too. Enums such as
    ResponseAction are strings (we made them inherit from `str`), so
    they save as text like "ISOLATE" automatically.
    """
    return asdict(decision)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class DecisionLogger:
    """Records decisions in memory and in an append-only file.

    Example:
        logger = DecisionLogger()
        logger.log(decision)
        print(logger.get_recent(5))
    """

    def __init__(
        self,
        log_file: Optional[str] = DEFAULT_LOG_FILE,
        max_in_memory: int = 1000,
    ) -> None:
        """Create the logger.

        Args:
            log_file:      Path of the audit file. Pass None to disable
                           file logging (memory only) - handy for tests.
            max_in_memory: How many decisions to keep in memory. Older ones
                           are dropped from memory but stay in the file.
        """
        self.log_file: Optional[Path] = Path(log_file) if log_file else None
        self.max_in_memory = max_in_memory
        self._history: List[Decision] = []

        # A lock makes sure two threads (e.g. two web requests at the same
        # moment) can't write to the file at the same time and garble it.
        self._lock = threading.Lock()

        # Make sure the folder for the log file exists.
        if self.log_file is not None:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------
    def log(self, decision: Decision) -> None:
        """Record one decision.

        Args:
            decision: The Decision returned by DecisionEngine.decide().
        """
        with self._lock:
            # 1. Keep it in memory (trim the oldest if we're over the limit).
            self._history.append(decision)
            if len(self._history) > self.max_in_memory:
                self._history.pop(0)

            # 2. Append it to the file as a single JSON line.
            if self.log_file is not None:
                line = json.dumps(
                    decision_to_dict(decision),
                    default=_json_default,
                )
                # "a" = append mode: adds to the end, never overwrites.
                with open(self.log_file, "a", encoding="utf-8") as file:
                    file.write(line + "\n")

        # 3. Also show a short summary in the console.
        console_logger.info(
            "Decision %s: %s (risk %s, confidence %.2f)",
            decision.decision_id,
            decision.action.value,
            decision.risk_assessment.risk_score,
            decision.confidence,
        )

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def get_history(self) -> List[Decision]:
        """Return a copy of all decisions currently kept in memory."""
        with self._lock:
            return list(self._history)

    def get_recent(self, count: int = 10) -> List[Decision]:
        """Return the newest `count` decisions (newest last)."""
        with self._lock:
            return list(self._history[-count:])

    def get_by_id(self, decision_id: str) -> Optional[Decision]:
        """Find one decision by its ID, or return None if not found."""
        with self._lock:
            for decision in self._history:
                if decision.decision_id == decision_id:
                    return decision
        return None

    def read_file_history(self) -> List[Dict[str, Any]]:
        """Read the complete audit file back as a list of dictionaries.

        This includes decisions from earlier runs of the program, which
        the in-memory list no longer contains.

        Returns:
            A list of dicts (oldest first). Empty if there is no file yet.
        """
        if self.log_file is None or not self.log_file.exists():
            return []

        records: List[Dict[str, Any]] = []
        with open(self.log_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line:  # skip blank lines
                    records.append(json.loads(line))
        return records