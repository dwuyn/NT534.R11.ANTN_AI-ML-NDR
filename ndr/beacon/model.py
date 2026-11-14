"""Shared D5 model helpers: anomaly normalization and SHAP extraction."""

from __future__ import annotations

from typing import Sequence

import numpy as np

from ndr.contracts import FeatureSnapshot, TopFeature
from ndr.features.baseline import BaselineProfile


def anomaly_raw(iforest, matrix: np.ndarray) -> np.ndarray:
    return -iforest.decision_function(matrix)


def normalize_anomaly(
    raw: np.ndarray, low: float, high: float
) -> np.ndarray:
    if high <= low:
        high = low + 1.0
    return np.clip((raw - low) / (high - low), 0.0, 1.0)


def shap_matrix(lgbm, matrix: np.ndarray) -> np.ndarray:
    contributions = np.asarray(
        lgbm.booster_.predict(matrix, pred_contrib=True), dtype=float
    )
    if contributions.ndim == 1:
        contributions = contributions.reshape(1, -1)
    return contributions[:, :-1]


def top_features(
    snapshot: FeatureSnapshot,
    baseline: BaselineProfile,
    contributions: np.ndarray,
    names: Sequence[str],
) -> list[TopFeature]:
    features = [
        TopFeature(
            name=name,
            value=float(snapshot.features[name]),
            z=float(
                (snapshot.features[name] - baseline.feature_mean.get(name, 0.0))
                / (baseline.feature_std.get(name, 1.0) or 1.0)
            ),
            shap=float(contribution),
        )
        for name, contribution in zip(names, contributions)
    ]
    return sorted(features, key=lambda feature: abs(feature.shap or 0.0), reverse=True)[
        :3
    ]
