#!/usr/bin/env python3
"""Generate a deterministic, checksum-valid classic-pcap file."""
from __future__ import annotations

from pathlib import Path
import sys

from kansoku.sample_pcap import generate_sample_pcap


def main() -> int:
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")
    print(generate_sample_pcap(output).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
