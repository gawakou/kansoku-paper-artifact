# KANSOKU v0.8.3

KANSOKU v0.8.3 is a virtual-lab reliability patch.

## Fixes

- Normalize native nftables JSON prefix operands such as
  `{"prefix":{"addr":"10.10.10.0","len":24}}` into CIDR strings before
  policy validation.
- Normalize native nftables JSON port ranges.
- Preserve support for fixture-style textual nftables operands.
- Show the actual FRRouting, Open vSwitch, or nftables collector error when a
  live-state collection step fails instead of discarding diagnostic output.
- Retain the detached HTTP/iperf3 startup and readiness checks introduced in
  v0.8.2.

## Validation

The automated suite includes native nftables JSON operands matching the output
shape produced by `nft -j list ruleset` in the Ubuntu virtual lab.
