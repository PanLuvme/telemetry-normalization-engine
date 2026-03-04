"""
AWS CloudTrail log normalizer.
Maps CloudTrail API events to OCSF event classes and unified field names.
"""

import json
from src.normalizers.base import BaseNormalizer
from src.ocsf_schema import OCSFEvent, Actor, Device, NetworkEndpoint


# CloudTrail eventName prefix → OCSF class
CLOUDTRAIL_CLASS_MAP = {
    "Create":   (6001, "API Activity", 1, "Create"),
    "Delete":   (6001, "API Activity", 2, "Delete"),
    "Describe": (6002, "API Activity", 3, "Read"),
    "Get":      (6002, "API Activity", 3, "Read"),
    "List":     (6002, "API Activity", 3, "Read"),
    "Put":      (6001, "API Activity", 4, "Update"),
    "Update":   (6001, "API Activity", 4, "Update"),
    "Assume":   (3002, "Account Change", 1, "Assume Role"),
    "Attach":   (6001, "API Activity", 5, "Attach"),
    "Detach":   (6001, "API Activity", 6, "Detach"),
    "Invoke":   (6003, "API Activity", 7, "Invoke"),
    "Start":    (6001, "API Activity", 8, "Start"),
    "Stop":     (6001, "API Activity", 9, "Stop"),
}

ERROR_SEVERITIES = {
    "AccessDenied": (4, "High"),
    "UnauthorizedAccess": (5, "Critical"),
    "InvalidClientTokenId": (3, "Medium"),
    "NoSuchEntity": (2, "Low"),
}


class CloudTrailNormalizer(BaseNormalizer):

    def _get_class_info(self, event_name: str):
        for prefix, info in CLOUDTRAIL_CLASS_MAP.items():
            if event_name.startswith(prefix):
                return info
        return (6001, "API Activity", 0, "Unknown")

    def normalize(self, raw: dict) -> OCSFEvent:
        # CloudTrail can be nested under .Records[]
        record = raw.get("Records", [raw])[0] if "Records" in raw else raw

        event_name = self._safe_str(record.get("eventName"))
        error_code = self._safe_str(record.get("errorCode"))
        error_msg = self._safe_str(record.get("errorMessage"))

        class_uid, class_name, activity_id, activity_name = self._get_class_info(event_name)

        # Severity based on error
        if error_code in ERROR_SEVERITIES:
            severity_id, severity = ERROR_SEVERITIES[error_code]
        elif error_code:
            severity_id, severity = (3, "Medium")
        else:
            severity_id, severity = (1, "Informational")

        status = "Failure" if error_code else "Success"

        user_identity = record.get("userIdentity", {})
        source_ip = self._safe_str(record.get("sourceIPAddress"))
        request_params = record.get("requestParameters") or {}
        response = record.get("responseElements") or {}

        event = OCSFEvent(
            class_uid=class_uid,
            class_name=class_name,
            activity_id=activity_id,
            activity_name=activity_name,
            severity_id=severity_id,
            severity=severity,
            status=status,
            time=self._safe_str(record.get("eventTime")),
            metadata_product_name="AWS CloudTrail",
            metadata_product_version=self._safe_str(record.get("eventVersion")),
            metadata_log_source="cloudtrail",
            raw_data=json.dumps(record),
        )

        # Actor
        event.actor = Actor(
            user=self._safe_str(
                user_identity.get("userName") or
                user_identity.get("principalId") or
                user_identity.get("arn")
            ),
            session_uid=self._safe_str(
                record.get("requestID")
            ),
        )

        # Device / source
        event.device = Device(
            hostname=self._safe_str(record.get("userAgent")),
        )
        event.src_endpoint = NetworkEndpoint(ip=source_ip)

        # Cloud / API metadata
        event.api_operation = event_name
        event.api_service_name = self._safe_str(record.get("eventSource"))
        event.cloud_region = self._safe_str(record.get("awsRegion"))
        event.cloud_account_uid = self._safe_str(
            user_identity.get("accountId")
        )

        # Tags for error context
        if error_code:
            event.tags.append(f"error:{error_code}")
        if record.get("readOnly"):
            event.tags.append("read_only")

        # Unmapped fields
        known = {"eventName", "errorCode", "errorMessage", "userIdentity",
                 "sourceIPAddress", "requestParameters", "responseElements",
                 "eventTime", "eventVersion", "eventSource", "awsRegion",
                 "requestID", "userAgent", "readOnly", "eventID", "eventType",
                 "recipientAccountId", "Records"}
        event.unmapped = {k: v for k, v in record.items() if k not in known}

        return event
