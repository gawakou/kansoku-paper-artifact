# KANSOKU v0.6.0

KANSOKU v0.6.0 introduces authenticated distributed observation.

## Added

- remote-agent registry with capabilities and labels;
- one-time tokens with PBKDF2-HMAC-SHA256 storage;
- token rotation and agent disable/enable;
- authenticated heartbeat and ingest HTTP endpoints;
- durable owner-only edge spool;
- FIFO retry and idempotent batch receipts;
- automatic state evaluation after remote ingest;
- remote-agent and ingest status in the dashboard;
- additive v0.5-to-v0.6 SQLite migration;
- four JSON schemas and ten new automated tests.

## Safety

The ingest API accepts observation evidence only. It does not expose policy, approval, controller, or system-action write endpoints. The built-in server does not provide TLS and should be placed behind HTTPS when used beyond a trusted environment.

## Release checklist

1. Expand the distribution into a clean directory and install with `python -m pip install -e '.[dev]'`.
2. Run `python -m compileall -q kansoku` and `python -m pytest -q`; expect 43 tests.
3. Run `./scripts/macos_smoke_test.sh` on macOS with iperf3 installed.
4. Confirm remote-agent creation, token-file permissions, ingest startup, edge delivery, heartbeat, and `/api/agents`.
5. Back up the v0.5 database and run `kansoku --db <db> init` to add v0.6 tables.
6. Confirm `.venv`, databases, raw artifacts, `.kansoku`, spool files, and agent-token files are ignored by Git.
7. Copy the package into the existing Git worktree with `rsync`, excluding runtime and secret files.
8. Reinstall the editable package and run `./scripts/pre_release_check.sh`.
9. Commit and push `Release KANSOKU v0.6.0` to `main`.
10. Create and push annotated tag `v0.6.0`.
11. Compare `HEAD`, `origin/main`, and `v0.6.0^{}`.
12. Confirm GitHub Actions and inspect the repository for accidental credentials or runtime evidence.
