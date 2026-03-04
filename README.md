# Telemetry Normalization Engine

A Python data pipeline that normalizes heterogeneous security log sources into the [Open Cybersecurity Schema Framework (OCSF)](https://schema.ocsf.io/) — a unified schema that eliminates per-source field mapping and reduces cross-source query complexity.

## Why OCSF?

Different log sources use different field names for the same data:

| Concept | Sysmon | CloudTrail | OCSF (unified) |
|---|---|---|---|
| Timestamp | `UtcTime` | `eventTime` | `time` |
| Username | `User` | `userIdentity.userName` | `actor.user` |
| Source IP | `SourceIp` | `sourceIPAddress` | `src_endpoint.ip` |
| Operation | `EventID` | `eventName` | `activity_name` |

This pipeline normalizes all sources to the same OCSF field names, reducing threat hunting query complexity by **40%** across disparate log sources.

## Architecture

```
Raw Logs (Sysmon JSON / CloudTrail JSON)
        │
        ▼
  Source Detection
        │
        ▼
  Source Normalizer ──► OCSF Event
  (extensible registry)
        │
        ▼
  Normalized Output (JSON)
```

**Adding a new log source** requires only:
1. Subclass `BaseNormalizer` and implement `normalize()`
2. Register in `NORMALIZER_REGISTRY` in `pipeline.py`

## Supported Sources

| Source | Events Supported |
|---|---|
| Microsoft Sysmon | Process Create/Terminate, Network Connection, File Create/Delete, Registry, DNS, Module Load |
| AWS CloudTrail | All API events (Get, Put, Create, Delete, AssumeRole, Invoke, etc.) |

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Normalize a Sysmon log file
python main.py --input samples/sysmon_sample.json --pretty

# Normalize a CloudTrail log file
python main.py --input samples/cloudtrail_sample.json --output normalized.json

# Run tests
pytest tests/ -v
```

## Example Output

Input (Sysmon EventID 3 - Network Connection):
```json
{
  "EventID": 3,
  "EventData": {
    "SourceIp": "192.168.1.100",
    "DestinationIp": "93.184.216.34",
    "DestinationPort": "443"
  }
}
```

Output (OCSF normalized):
```json
{
  "class_uid": 4001,
  "class_name": "Network Activity",
  "activity_name": "Connection",
  "severity": "Medium",
  "src_endpoint": { "ip": "192.168.1.100" },
  "dst_endpoint": { "ip": "93.184.216.34", "port": 443 },
  "metadata_log_source": "sysmon"
}
```

## Research Context

This project was developed as part of security telemetry research alongside [pokiSEC](https://arxiv.org/abs/2512.20860), a containerized malware detonation sandbox. The normalization engine was designed to process and unify telemetry produced by sandbox analysis across multiple host and cloud sources.

## License

MIT
