"""Threshold helpers shared by supervised detector slices."""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np


def ensure_above_benign(
    threshold: float, benign_scores: Sequence[float]
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
    if value >= max_benign:
        value = float(np.nextafter(max_benign, np.inf))
    if not 0.0 < value < 1.0:
        raise ValueError(
            f"calibration produced no separable threshold ({value}); "
            "benign scores reach 1.0"
        )
    return value
