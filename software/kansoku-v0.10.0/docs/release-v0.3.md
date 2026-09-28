# v0.3 release procedure

Run these steps from a clone of `git@github.com:gawakou/kansoku.git` after copying the v0.3 source into the clone while excluding `.git`, `.venv`, databases, and raw artifacts.

## 1. Clean installation and automated tests

```bash
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m compileall -q kansoku
python -m pytest -q
./scripts/macos_smoke_test.sh
```

## 2. Confirm package and CLI version

```bash
python -c "import importlib.metadata as m; print(m.version('kansoku'))"
kansoku --help
kansoku profile --help
kansoku agent watch --help
```

Expected package version: `0.3.0`.

## 3. Confirm no runtime data will be committed

```bash
git status --short
git status --ignored --short
git check-ignore -v .venv kansoku.db artifacts/raw/example.json
```

Do not commit `.venv`, `*.db`, `*.sqlite*`, `artifacts/raw/*.json`, `.DS_Store`, credentials, or environment-specific secrets.

## 4. Commit and push main

```bash
git add .
git diff --cached --stat
git commit -m "Release KANSOKU v0.3.0"
git push origin main
```

## 5. Create and push the release tag

```bash
git tag -a v0.3.0 -m "KANSOKU v0.3.0"
git push origin v0.3.0
git fetch origin --tags
```

## 6. Verify branch/tag consistency

```bash
git rev-parse --short HEAD
git rev-parse --short origin/main
git rev-parse --short v0.3.0
git log --oneline --decorate -4
```

All three revisions must be identical. Verify that GitHub Actions passes on Python 3.10 and 3.12 and that GitHub displays the v0.3 README and tag.
