# KANSOKU v0.7.1

KANSOKU v0.7.1 adds a privacy-aware packet and flow observation layer to the authenticated distributed Agent/Hub architecture.

## Maintenance fixes in 0.7.1

- identical offline imports are idempotent by target, source, and SHA-256;
- `--force-reimport` explicitly creates a separate analysis session;
- remote batches suppress identical captures even when batch IDs differ;
- generated sample packets have valid IPv4/TCP/UDP checksums and valid mDNS structure.

## Highlights

- live tcpdump capture with BPF filtering;
- 96-byte header-only default and explicit full-packet opt-in;
- dependency-free classic-pcap parser;
- IPv4/IPv6, TCP/UDP/ICMP, VLAN, and directional flow aggregation;
- capture provenance and SHA-256 identity;
- retention and quota enforcement;
- remote delivery of metadata and bounded flows without raw pcap upload;
- capture/flow CLI and Dashboard views;
- additive database migration;
- 55 automated tests.

## Compatibility

v0.1-v0.6 databases are migrated additively. Existing remote batches and receipts remain readable. New remote batches add `captures` and `flows`; new receipts add corresponding counts.

## Known limitations

- pcapng is not parsed in v0.7;
- live tcpdump may require elevated capture privileges;
- flow aggregation is directional and capture-local, without long-window stitching;
- encrypted payload is not decrypted;
- raw pcap retrieval from edge agents is intentionally not implemented.
