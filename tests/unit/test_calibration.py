from __future__ import annotations

import pytest

from ndr.features.calibration import ensure_above_benign


def test_zero_threshold_moves_above_collapsed_benign_mass() -> None:
    threshold = ensure_above_benign(0.0, [0.0, 0.0, 0.0])
    assert threshold > 0.0


def test_positive_quantile_is_not_forced_above_max_benign() -> None:
    assert ensure_above_benign(0.5, [0.2, 0.8]) == 0.5


def test_empty_benign_scores_are_rejected() -> None:
    with pytest.raises(ValueError, match="no benign windows"):
        ensure_above_benign(0.5, [])
