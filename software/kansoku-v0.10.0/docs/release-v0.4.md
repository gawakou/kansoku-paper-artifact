# KANSOKU v0.4 release checklist

1. Create a clean Python virtual environment.
2. Install with `python -m pip install -e '.[dev]'`.
3. Run `python -m compileall -q kansoku`.
4. Run all tests and confirm `24 passed`.
5. Run `./scripts/macos_smoke_test.sh` on macOS.
6. Confirm policy, approval, controller, verification, and dashboard output.
7. Run `./scripts/pre_release_check.sh`.
8. Confirm DBs, raw artifacts, virtual environments, and secrets are ignored.
9. Commit to the existing `main` branch and push.
10. Create and push annotated tag `v0.4.0`.
11. Compare the dereferenced tag commit with `HEAD` and `origin/main`:

```bash
git rev-parse --short HEAD
git rev-parse --short origin/main
git rev-parse --short 'v0.4.0^{}'
```

Annotated tag object IDs may differ from commit IDs; always dereference with `^{}`.
