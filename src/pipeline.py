"""
Telemetry Normalization Pipeline
Normalizes heterogeneous log sources (Sysmon, CloudTrail) into OCSF schema.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from src.normalizers.sysmon import SysmonNormalizer
from src.normalizers.cloudtrail import CloudTrailNormalizer
from src.ocsf_schema import OCSFEvent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


NORMALIZER_REGISTRY = {
    "sysmon": SysmonNormalizer,
    "cloudtrail": CloudTrailNormalizer,
}


class TelemetryPipeline:
    """
    Core pipeline: ingest raw logs, detect source, normalize to OCSF.
    New sources can be onboarded by registering a normalizer in NORMALIZER_REGISTRY.
    """

    def __init__(self):
        self.normalizers = {k: v() for k, v in NORMALIZER_REGISTRY.items()}
        self.stats = {"processed": 0, "failed": 0, "by_source": {}}

    def detect_source(self, raw: dict) -> str:
        """Detect log source from raw event structure."""
        if "EventID" in raw or "System" in raw:
            return "sysmon"
        if "eventVersion" in raw or "userIdentity" in raw:
            return "cloudtrail"
        raise ValueError(f"Unknown log source. Keys: {list(raw.keys())[:5]}")

    def process(self, raw: dict) -> OCSFEvent:
        """Normalize a single raw log event into OCSF."""
        source = self.detect_source(raw)
        normalizer = self.normalizers[source]
        event = normalizer.normalize(raw)

        self.stats["processed"] += 1
        self.stats["by_source"][source] = self.stats["by_source"].get(source, 0) + 1
        return event

    def process_batch(self, events: list[dict]) -> tuple[list[OCSFEvent], list[dict]]:
        """Process a batch of raw events. Returns (normalized, failed)."""
        normalized, failed = [], []
        for raw in events:
            try:
                normalized.append(self.process(raw))
            except Exception as e:
                self.stats["failed"] += 1
                logger.warning(f"Failed to normalize event: {e}")
                failed.append({"raw": raw, "error": str(e)})
        logger.info(
            f"Batch complete: {len(normalized)} normalized, {len(failed)} failed. "
            f"Stats: {self.stats}"
        )
        return normalized, failed

    def process_file(self, path: str) -> tuple[list[OCSFEvent], list[dict]]:
        """Load a NDJSON or JSON array file and process all events."""
        events = []
        with open(path, "r") as f:
            content = f.read().strip()
            try:
                data = json.loads(content)
                events = data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                for line in content.splitlines():
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        logger.info(f"Loaded {len(events)} events from {path}")
        return self.process_batch(events)
