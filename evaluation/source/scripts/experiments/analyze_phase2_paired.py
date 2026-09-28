#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import math


RECORDS = Path(
    "artifacts/paper/phase2-evaluation-v1/"
    "records-all.json"
)

METHODS = (
    "CONFIG_ONLY",
    "FLOW_ONLY",
    "PROPOSED",
)


def holm_adjust(pvalues):
    ordered = sorted(
        enumerate(pvalues),
        key=lambda x: x[1],
    )

    adjusted = [0.0] * len(pvalues)
    running = 0.0
    m = len(pvalues)

    for rank, (idx, p) in enumerate(ordered):
        value = min(
            1.0,
            (m - rank) * p,
        )
        running = max(running, value)
        adjusted[idx] = running

    return adjusted


def cochran_q(rows):
    # rows: list[list[int]], n subjects x k methods
    n = len(rows)
    k = len(rows[0])

    col = [
        sum(row[j] for row in rows)
        for j in range(k)
    ]
    row_sums = [
        sum(row)
        for row in rows
    ]

    total = sum(col)

    numerator = (
        (k - 1)
        * (
            k * sum(x * x for x in col)
            - total * total
        )
    )

    denominator = (
        k * total
        - sum(x * x for x in row_sums)
    )

    if denominator == 0:
        return None, None

    q = numerator / denominator
    # Cochran's Q has k-1 degrees of freedom.
    # Here k is fixed at 3, so df=2 and the
    # chi-square survival function is exp(-q/2).
    if k != 3:
        raise ValueError(
            "this implementation expects exactly 3 methods"
        )

    p = math.exp(-q / 2.0)

    return q, p


def exact_mcnemar(rows, a, b):
    ia = METHODS.index(a)
    ib = METHODS.index(b)

    a_only = sum(
        row[ia] == 1 and row[ib] == 0
        for row in rows
    )
    b_only = sum(
        row[ia] == 0 and row[ib] == 1
        for row in rows
    )

    discordant = a_only + b_only

    if discordant == 0:
        p = 1.0
    else:
        # Exact two-sided McNemar test.
        # Under H0, discordant outcomes follow
        # Binomial(n=discordant, p=0.5).
        tail = min(a_only, b_only)

        lower_tail = sum(
            math.comb(discordant, i)
            for i in range(tail + 1)
        ) / (2 ** discordant)

        p = min(1.0, 2.0 * lower_tail)

    return a_only, b_only, p


records = json.loads(RECORDS.read_text())

# Primary accuracy only.
records = [
    r
    for r in records
    if r["repetition"] == 1
]

by_instance = defaultdict(dict)
prototype_of = {}

for r in records:
    iid = r["instance_id"]
    method = r["method"]

    by_instance[iid][method] = int(
        r["strict_correct"]
    )

    prototype_of[iid] = r["prototype_id"]


instance_rows = []

for iid in sorted(by_instance):
    instance_rows.append(
        [
            by_instance[iid][m]
            for m in METHODS
        ]
    )


# Collapse to prototype level.
by_prototype = defaultdict(
    lambda: defaultdict(list)
)

for iid, result in by_instance.items():
    prototype = prototype_of[iid]

    for method in METHODS:
        by_prototype[prototype][method].append(
            result[method]
        )


prototype_rows = []

for prototype in sorted(by_prototype):
    row = []

    for method in METHODS:
        values = by_prototype[prototype][method]

        if len(set(values)) != 1:
            raise ValueError(
                f"prototype not internally stable: "
                f"{prototype} {method} {values}"
            )

        row.append(values[0])

    prototype_rows.append(row)


pairs = (
    ("PROPOSED", "CONFIG_ONLY"),
    ("PROPOSED", "FLOW_ONLY"),
    ("CONFIG_ONLY", "FLOW_ONLY"),
)


def report(name, rows):
    print()
    print("=" * 72)
    print(name, "N =", len(rows))
    print("=" * 72)

    q, q_p = cochran_q(rows)

    print(
        f"Cochran Q = {q:.6f}, "
        f"df=2, p={q_p:.12g}"
    )

    raw = []

    results = []

    for a, b in pairs:
        a_only, b_only, p = exact_mcnemar(
            rows,
            a,
            b,
        )

        raw.append(p)
        results.append(
            (a, b, a_only, b_only, p)
        )

    adjusted = holm_adjust(raw)

    for (
        a,
        b,
        a_only,
        b_only,
        p,
    ), p_holm in zip(results, adjusted):
        print(
            f"{a:12s} vs {b:12s}: "
            f"{a}_only={a_only}, "
            f"{b}_only={b_only}, "
            f"exact_p={p:.12g}, "
            f"holm_p={p_holm:.12g}"
        )


report(
    "INSTANCE-LEVEL",
    instance_rows,
)

report(
    "PROTOTYPE-LEVEL SENSITIVITY",
    prototype_rows,
)
