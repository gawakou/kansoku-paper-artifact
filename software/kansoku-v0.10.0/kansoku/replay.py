from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, List

from .models import Domain, Observation


class CsvReplay:
    """Replay observations from a simple CSV file.

    Required columns:
    timestamp,target,source,domain,metric,value,unit,method
    """

    required_columns = {"timestamp", "target", "source", "domain", "metric", "value", "unit", "method"}

    def load(self, path: str | Path) -> List[Observation]:
        path = Path(path)
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise ValueError("CSV file has no header")
            missing = self.required_columns - set(reader.fieldnames)
            if missing:
                raise ValueError(f"CSV file is missing required columns: {sorted(missing)}")
            observations: List[Observation] = []
            for row in reader:
                observations.append(
                    Observation(
                        timestamp=row["timestamp"],
                        target=row["target"],
                        source=row["source"],
                        domain=row["domain"] or Domain.NETWORK.value,
                        metric=row["metric"],
                        value=float(row["value"]),
                        unit=row["unit"],
                        method=row["method"],
                    )
                )
        return observations
