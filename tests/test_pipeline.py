"""
Unit tests for the Telemetry Normalization Pipeline.
"""

import json
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.pipeline import TelemetryPipeline
from src.normalizers.sysmon import SysmonNormalizer
from src.normalizers.cloudtrail import CloudTrailNormalizer


# ── Fixtures ──────────────────────────────────────────────────────────────────

SYSMON_PROCESS_CREATE = {
    "EventID": 1,
    "EventData": {
        "UtcTime": "2025-11-01T14:23:01.000Z",
        "User": "DESKTOP-ABC\\john",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ProcessId": "4812",
        "CommandLine": "cmd.exe /c whoami",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "MD5": "a72c9b1d",
        "SHA256": "e3b0c442",
    },
    "System": {"Computer": "DESKTOP-ABC", "Version": "13.40"},
}

SYSMON_NETWORK = {
    "EventID": 3,
    "EventData": {
        "UtcTime": "2025-11-01T14:23:05.000Z",
        "User": "DESKTOP-ABC\\john",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ProcessId": "4812",
        "SourceIp": "192.168.1.100",
        "SourcePort": "49823",
        "DestinationIp": "93.184.216.34",
        "DestinationPort": "443",
        "DestinationHostname": "example.com",
    },
    "System": {"Computer": "DESKTOP-ABC"},
}

CLOUDTRAIL_GET = {
    "eventVersion": "1.09",
    "userIdentity": {"userName": "Alice", "accountId": "123456789012"},
    "eventTime": "2025-11-01T20:30:00Z",
    "eventSource": "s3.amazonaws.com",
    "eventName": "GetObject",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.42",
    "requestID": "REQ001",
    "readOnly": True,
}

CLOUDTRAIL_ERROR = {
    "eventVersion": "1.09",
    "userIdentity": {"userName": "Bob", "accountId": "123456789012"},
    "eventTime": "2025-11-01T21:05:12Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "AssumeRole",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "198.51.100.77",
    "errorCode": "AccessDenied",
    "errorMessage": "User is not authorized",
    "requestID": "REQ002",
    "readOnly": False,
}


# ── Sysmon Tests ───────────────────────────────────────────────────────────────

class TestSysmonNormalizer:

    def test_process_create_class(self):
        norm = SysmonNormalizer()
        event = norm.normalize(SYSMON_PROCESS_CREATE)
        assert event.class_uid == 4001
        assert event.activity_name == "Launch"
        assert event.metadata_log_source == "sysmon"

    def test_process_create_actor(self):
        norm = SysmonNormalizer()
        event = norm.normalize(SYSMON_PROCESS_CREATE)
        assert "john" in event.actor.user
        assert "cmd.exe" in event.process_name

    def test_process_create_cmd_line(self):
        norm = SysmonNormalizer()
        event = norm.normalize(SYSMON_PROCESS_CREATE)
        assert event.process_cmd_line == "cmd.exe /c whoami"

    def test_network_endpoints(self):
        norm = SysmonNormalizer()
        event = norm.normalize(SYSMON_NETWORK)
        assert event.src_endpoint.ip == "192.168.1.100"
        assert event.dst_endpoint.ip == "93.184.216.34"
        assert event.dst_endpoint.port == 443
        assert event.dst_endpoint.hostname == "example.com"

    def test_raw_data_preserved(self):
        norm = SysmonNormalizer()
        event = norm.normalize(SYSMON_PROCESS_CREATE)
        assert event.raw_data is not None
        raw = json.loads(event.raw_data)
        assert raw["EventID"] == 1


# ── CloudTrail Tests ───────────────────────────────────────────────────────────

class TestCloudTrailNormalizer:

    def test_get_object_class(self):
        norm = CloudTrailNormalizer()
        event = norm.normalize(CLOUDTRAIL_GET)
        assert event.activity_name == "Read"
        assert event.status == "Success"
        assert event.severity == "Informational"

    def test_access_denied_severity(self):
        norm = CloudTrailNormalizer()
        event = norm.normalize(CLOUDTRAIL_ERROR)
        assert event.severity == "High"
        assert event.status == "Failure"
        assert "error:AccessDenied" in event.tags

    def test_cloud_metadata(self):
        norm = CloudTrailNormalizer()
        event = norm.normalize(CLOUDTRAIL_GET)
        assert event.cloud_region == "us-east-1"
        assert event.api_operation == "GetObject"
        assert event.api_service_name == "s3.amazonaws.com"
        assert event.cloud_account_uid == "123456789012"

    def test_actor_user(self):
        norm = CloudTrailNormalizer()
        event = norm.normalize(CLOUDTRAIL_GET)
        assert event.actor.user == "Alice"


# ── Pipeline Tests ─────────────────────────────────────────────────────────────

class TestPipeline:

    def test_detect_sysmon(self):
        pipeline = TelemetryPipeline()
        assert pipeline.detect_source(SYSMON_PROCESS_CREATE) == "sysmon"

    def test_detect_cloudtrail(self):
        pipeline = TelemetryPipeline()
        assert pipeline.detect_source(CLOUDTRAIL_GET) == "cloudtrail"

    def test_batch_processing(self):
        pipeline = TelemetryPipeline()
        events = [SYSMON_PROCESS_CREATE, SYSMON_NETWORK, CLOUDTRAIL_GET, CLOUDTRAIL_ERROR]
        normalized, failed = pipeline.process_batch(events)
        assert len(normalized) == 4
        assert len(failed) == 0

    def test_batch_stats(self):
        pipeline = TelemetryPipeline()
        pipeline.process_batch([SYSMON_PROCESS_CREATE, CLOUDTRAIL_GET])
        assert pipeline.stats["processed"] == 2
        assert pipeline.stats["by_source"]["sysmon"] == 1
        assert pipeline.stats["by_source"]["cloudtrail"] == 1

    def test_unified_field_names(self):
        """Both sources should produce events with the same field schema."""
        pipeline = TelemetryPipeline()
        sysmon_event = pipeline.process(SYSMON_PROCESS_CREATE)
        ct_event = pipeline.process(CLOUDTRAIL_GET)
        # Both should have the same top-level fields
        assert set(sysmon_event.to_dict().keys()) == set(ct_event.to_dict().keys())

    def test_unknown_source_raises(self):
        pipeline = TelemetryPipeline()
        with pytest.raises(ValueError):
            pipeline.detect_source({"unknown_field": "value"})
