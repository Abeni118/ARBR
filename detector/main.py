"""
Entrypoint for the detection service.

Usage:
    python -m detector.main --tail            # follow live alerts.json
    python -m detector.main --replay sample.json   # process a file once (testing)

The --tail mode is meant to run on/near the Wazuh manager (or wherever
alerts.json is accessible). In a real deployment this would more likely
subscribe to the Wazuh API's alert stream or a message queue instead of
tailing a local file - swap the source in run() when that's available.
"""
import argparse
import json
import logging
import time

from . import config
from .processor import process_alert
from .sink import DetectionSink

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("detector.main")


def _iter_new_lines(path: str):
    """Follow a file like `tail -f`, yielding new lines as they appear."""
    with open(path, "r") as f:
        f.seek(0, 2)  # jump to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def _iter_file_lines(path: str):
    """Read a file once, line by line (for --replay testing)."""
    with open(path, "r") as f:
        for line in f:
            if line.strip():
                yield line


def run(lines_iter, sink: DetectionSink):
    for line in lines_iter:
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        for detection in process_alert(alert):
            sink.write(detection)
            log.info("Detection written: %s (%s, %s)",
                      detection.detection_id, detection.detection_type,
                      detection.severity)


def main():
    parser = argparse.ArgumentParser(description="Wazuh ransomware detection service")
    parser.add_argument("--tail", action="store_true",
                         help="Follow the live alerts.json file")
    parser.add_argument("--replay", metavar="FILE",
                         help="Process a JSON-lines alert file once, then exit")
    parser.add_argument("--alerts-path", default=config.ALERTS_JSON_PATH,
                         help="Path to alerts.json (default: %(default)s)")
    args = parser.parse_args()

    sink = DetectionSink()

    if args.replay:
        log.info("Replaying alerts from %s", args.replay)
        run(_iter_file_lines(args.replay), sink)
    elif args.tail:
        log.info("Tailing %s for new alerts...", args.alerts_path)
        run(_iter_new_lines(args.alerts_path), sink)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
