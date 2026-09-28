from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from .models import CollectionRun


def save_collection_run(run: CollectionRun, directory: Union[str, Path]) -> Path:
    """Persist one raw collection run as a readable JSON artifact."""
    output_dir = Path(directory)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{run.run_id}.json"
    path.write_text(json.dumps(run.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return path
