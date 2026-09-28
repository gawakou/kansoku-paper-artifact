# KANSOKU v0.5 release checklist

1. Install in a clean virtual environment.
2. Confirm package version `0.5.0` and CLI commands `target` and `service`.
3. Run `python -m compileall -q kansoku`.
4. Run `python -m pytest -q` and confirm 33 tests pass.
5. Run `./scripts/macos_smoke_test.sh` on macOS.
6. Confirm target registration, one real service cycle, scheduler-cycle persistence, and lease cleanup.
7. Confirm `/api/fleet` and target snapshot data.
8. Run `./scripts/pre_release_check.sh` in the Git worktree.
9. Confirm databases, raw evidence, virtual environments, and secrets are ignored.
10. Commit and push `main`.
11. Create and push annotated tag `v0.5.0`.
12. Compare `HEAD`, `origin/main`, and `v0.5.0^{}`.
