#!/usr/bin/env python3
"""
CLI entrypoint for the Telemetry Normalization Pipeline.

Usage:
    python main.py --input samples/sysmon_sample.json
    python main.py --input samples/cloudtrail_sample.json --output output.json
    python main.py --input samples/sysmon_sample.json --pretty
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.pipeline import TelemetryPipeline


def main():
    parser = argparse.ArgumentParser(
        description="Normalize Sysmon/CloudTrail logs into OCSF schema"
    )
    parser.add_argument("--input", "-i", required=True, help="Path to input JSON/NDJSON file")
    parser.add_argument("--output", "-o", help="Path to output file (default: stdout)")
    parser.add_argument("--pretty", action="store_true", help="Pretty print output")
    args = parser.parse_args()

    pipeline = TelemetryPipeline()
    normalized, failed = pipeline.process_file(args.input)

    indent = 2 if args.pretty else None
    output = json.dumps(
        [e.to_dict() for e in normalized],
        indent=indent,
        default=str
    )

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"✓ Wrote {len(normalized)} normalized events to {args.output}")
        if failed:
            print(f"⚠ {len(failed)} events failed normalization")
    else:
        print(output)

    print(f"\nStats: {pipeline.stats}", file=sys.stderr)


if __name__ == "__main__":
    main()
