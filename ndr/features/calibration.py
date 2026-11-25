"""Threshold helpers shared by supervised detector slices."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np


def ensure_above_benign(
    threshold: float,
    benign_scores: Sequence[float],
    val_scores: Sequence[float] | None = None,
    val_labels: Sequence[int] | None = None,
    min_guard_recall: float = 0.5,
) -> float:
    """Keep a threshold strictly above the validation benign mass.

    Isotonic calibration on cleanly separable validation data often maps all
    benign windows to exactly ``0.0``. A quantile threshold equal to that mass
    would flag every benign window under ``score >= threshold``, so move it to
    the next representable float above the maximum benign score.
    """

    if len(benign_scores) == 0:
        raise ValueError("validation has no benign windows")
    max_benign = float(np.max(np.asarray(benign_scores, dtype=float)))
    value = float(threshold)
    guard = float(np.nextafter(max_benign, np.inf))
    if value <= 0.0:
        # Isotonic can collapse the benign mass to exactly zero. A zero
        # threshold would classify every benign score as alert under
        # `score >= threshold`; move just above the collapsed mass.
        value = guard
    if val_scores is not None and val_labels is not None:
        scores = np.asarray(val_scores, dtype=float)
        labels = np.asarray(val_labels, dtype=int)
        positives = scores[labels == 1]
        if len(positives):
            guard_recall = float(np.mean(positives >= guard))
            if guard_recall >= min_guard_recall:
                value = max(value, guard)
    if not 0.0 < value < 1.0:
        raise ValueError(
            f"calibration produced no separable threshold ({value}); "
            "benign scores reach 1.0"
        )
    return value
