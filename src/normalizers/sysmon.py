"""
Sysmon log normalizer.
Maps Windows Sysmon EventIDs to OCSF event classes and unified field names.
"""

import json
from datetime import datetime, timezone
from src.normalizers.base import BaseNormalizer
from src.ocsf_schema import OCSFEvent, Actor, Device, NetworkEndpoint


# Sysmon EventID → OCSF class_uid + class_name + activity
SYSMON_EVENT_MAP = {
    1:  (4001, "Process Activity", 1, "Launch"),
    3:  (4001, "Network Activity", 1, "Connection"),
    5:  (4001, "Process Activity", 2, "Terminate"),
    6:  (4004, "Module Activity", 1, "Load"),
    7:  (4004, "Module Activity", 1, "Load"),
    8:  (4001, "Process Activity", 3, "Inject"),
    10: (4001, "Process Activity", 4, "Access"),
    11: (4001, "File System Activity", 1, "Create"),
    12: (4001, "Registry Key Activity", 1, "Create/Delete"),
    13: (4001, "Registry Value Activity", 1, "Set"),
    15: (4001, "File System Activity", 2, "Stream"),
    22: (4001, "DNS Activity", 1, "Query"),
    23: (4001, "File System Activity", 3, "Delete"),
}

SEVERITY_MAP = {
    1: (1, "Informational"),
    3: (3, "Medium"),
    7: (3, "Medium"),
    8: (5, "Critical"),
    10: (4, "High"),
    22: (2, "Low"),
}


class SysmonNormalizer(BaseNormalizer):

    def normalize(self, raw: dict) -> OCSFEvent:
        event_id = self._safe_int(raw.get("EventID") or
                                   raw.get("System", {}).get("EventID", 0))
        event_data = raw.get("EventData", raw)
        system = raw.get("System", {})

        class_uid, class_name, activity_id, activity_name = SYSMON_EVENT_MAP.get(
            event_id, (0, "Unknown", 0, "Unknown")
        )
        severity_id, severity = SEVERITY_MAP.get(event_id, (1, "Informational"))

        # Parse timestamp
        ts = self._safe_str(
            event_data.get("UtcTime") or
            system.get("TimeCreated", {}).get("@SystemTime", "")
        )

        event = OCSFEvent(
            class_uid=class_uid,
            class_name=class_name,
            activity_id=activity_id,
            activity_name=activity_name,
            severity_id=severity_id,
            severity=severity,
            status="Success",
            time=ts,
            metadata_product_name="Microsoft Sysmon",
            metadata_product_version=self._safe_str(system.get("Version", "")),
            metadata_log_source="sysmon",
            raw_data=json.dumps(raw),
        )

        # Actor
        event.actor = Actor(
            user=self._safe_str(event_data.get("User")),
            process=self._safe_str(event_data.get("Image")),
            session_uid=self._safe_str(event_data.get("LogonId")),
        )

        # Device
        event.device = Device(
            hostname=self._safe_str(
                system.get("Computer") or event_data.get("Computer")
            )
        )

        # Process fields
        event.process_name = self._safe_str(event_data.get("Image"))
        event.process_pid = self._safe_int(event_data.get("ProcessId"))
        event.process_cmd_line = self._safe_str(event_data.get("CommandLine"))
        event.parent_process_name = self._safe_str(event_data.get("ParentImage"))

        # Network fields (EventID 3)
        if event_id == 3:
            event.src_endpoint = NetworkEndpoint(
                ip=self._safe_str(event_data.get("SourceIp")),
                port=self._safe_int(event_data.get("SourcePort")),
            )
            event.dst_endpoint = NetworkEndpoint(
                ip=self._safe_str(event_data.get("DestinationIp")),
                port=self._safe_int(event_data.get("DestinationPort")),
                hostname=self._safe_str(event_data.get("DestinationHostname")),
            )

        # File fields
        event.file_path = self._safe_str(event_data.get("TargetFilename") or
                                          event_data.get("ImageLoaded"))
        event.file_hash_md5 = self._safe_str(event_data.get("MD5"))
        event.file_hash_sha256 = self._safe_str(event_data.get("SHA256"))

        # Collect unmapped fields
        known = {"EventID", "EventData", "System", "UtcTime", "User", "Image",
                 "ProcessId", "CommandLine", "ParentImage", "SourceIp", "SourcePort",
                 "DestinationIp", "DestinationPort", "DestinationHostname",
                 "TargetFilename", "ImageLoaded", "MD5", "SHA256", "LogonId"}
        event.unmapped = {k: v for k, v in raw.items() if k not in known}

        return event
