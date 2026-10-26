from __future__ import annotations

import hashlib
import io
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import numpy as np
import pandas as pd
from argon2 import PasswordHasher
from fastapi import HTTPException
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.metrics import mean_absolute_error, mean_squared_error
from statsmodels.tsa.holtwinters import ExponentialSmoothing

ph = PasswordHasher()
REQUIRED = {"timestamp", "traffic_mbps", "segment_id"}
DEVICE_REQUIRED = {"timestamp", "ap_or_building", "device_count", "traffic_mbps"}


def validate_csv(content: bytes, interval_minutes: int = 60) -> tuple[pd.DataFrame, dict[str, Any]]:
    try:
        raw = pd.read_csv(io.BytesIO(content))
    except Exception as exc:
        raise HTTPException(400, "Could not read CSV. Check the file encoding and delimiter.") from exc
    missing = REQUIRED - set(raw.columns)
    if missing:
        raise HTTPException(400, f"Missing required columns: {', '.join(sorted(missing))}")
    parsed = pd.to_datetime(raw.timestamp, errors="coerce", utc=True)
    numeric = pd.to_numeric(raw.traffic_mbps, errors="coerce")
    invalid_time = int(parsed.isna().sum())
    nonnumeric = int(numeric.isna().sum())
    negative = int((numeric < 0).fillna(False).sum())
    frame = raw.assign(timestamp=parsed, traffic_mbps=numeric)
    valid = frame.dropna(subset=["timestamp", "traffic_mbps", "segment_id"]).copy()
    valid = valid[valid.traffic_mbps >= 0]
    dup = int(valid.duplicated(["timestamp", "segment_id"] + (["direction"] if "direction" in valid else []), keep="first").sum())
    valid = valid.drop_duplicates(["timestamp", "segment_id"] + (["direction"] if "direction" in valid else []), keep="first")
    missing_intervals = 0
    for _, group in valid.groupby("segment_id"):
        stamps = pd.DatetimeIndex(group.timestamp.drop_duplicates().sort_values())
        if len(stamps) > 1:
            expected = pd.date_range(stamps.min(), stamps.max(), freq=f"{interval_minutes}min")
            missing_intervals += max(0, len(expected.difference(stamps)))
    report = {"rows_read": len(raw), "invalid_timestamps": invalid_time, "non_numeric_values": nonnumeric,
              "negative_values": negative, "duplicates": dup, "missing_intervals": missing_intervals,
              "missing_interval_assumption_minutes": interval_minutes,
              "date_range": [valid.timestamp.min().isoformat(), valid.timestamp.max().isoformat()] if len(valid) else None,
              "rows_accepted": len(valid)}
    if not len(valid) or invalid_time or nonnumeric or negative or dup:
        raise HTTPException(422, detail={"message": "CSV rejected. Correct invalid or duplicate rows and upload again.", "validation": report})
    return valid.sort_values(["segment_id", "timestamp"]), report


def chronological_split(values: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    n = len(values)
    a, b = int(n * .70), int(n * .85)
    if n < 20 or a < 2 or b <= a or b >= n:
        raise ValueError("At least 20 ordered observations are required for a 70/15/15 split.")
    return values[:a], values[a:b], values[b:]


def _metrics(actual: np.ndarray, pred: np.ndarray) -> dict[str, float]:
    return {"mae_mbps": float(mean_absolute_error(actual, pred)), "rmse_mbps": float(mean_squared_error(actual, pred) ** .5)}


def _lags(series: np.ndarray, start: int, end: int, season: int) -> tuple[np.ndarray, np.ndarray]:
    x, y = [], []
    for i in range(max(start, season), end):
        x.append([series[i - 1], series[max(0, i - 2)], series[max(0, i - season)]])
        y.append(series[i])
    return np.asarray(x), np.asarray(y)


def forecast(values: list[float], horizon: int = 24, season: int = 24) -> dict[str, Any]:
    data = np.asarray(values, dtype=float)
    train, validation, holdout = chronological_split(data)
    # Validation and test points are forecast recursively from the training history; actual future values never enter features.
    def naive(history: np.ndarray, n: int, period: int = season) -> np.ndarray:
        return np.array([history[-period + (i % period)] if len(history) >= period else history[-1] for i in range(n)])
    # Compare daily and weekly seasonal-naive baselines on validation. A 24-hour
    # baseline alone can underpredict weekdays after a quieter weekend.
    baseline_period = season
    base_val = naive(train, len(validation), baseline_period)
    if len(train) >= 168:
        weekly_val = naive(train, len(validation), 168)
        if (_metrics(validation, weekly_val)["mae_mbps"], _metrics(validation, weekly_val)["rmse_mbps"]) < (_metrics(validation, base_val)["mae_mbps"], _metrics(validation, base_val)["rmse_mbps"]):
            baseline_period = 168
            base_val = weekly_val
    history_for_holdout = np.concatenate([train, validation])
    base_test = naive(history_for_holdout, len(holdout), baseline_period)
    candidates: dict[str, tuple[np.ndarray, np.ndarray]] = {}
    try:
        model = ExponentialSmoothing(train, trend="add", seasonal="add", seasonal_periods=season, initialization_method="estimated").fit(optimized=True)
        history = np.concatenate([train, validation])
        holdout_model = ExponentialSmoothing(history, trend="add", seasonal="add", seasonal_periods=season, initialization_method="estimated").fit(optimized=True)
        candidates["holt_winters"] = (model.forecast(len(validation)), holdout_model.forecast(len(holdout)))
    except Exception:
        pass
    try:
        xtr, ytr = _lags(data, 0, len(train), season)
        if len(ytr) >= 5:
            gb = HistGradientBoostingRegressor(max_iter=100, max_leaf_nodes=7, l2_regularization=1.0, random_state=17).fit(xtr, ytr)
            history = np.concatenate([train, validation])
            xhist, yhist = _lags(history, 0, len(history), season)
            gb_holdout = HistGradientBoostingRegressor(max_iter=100, max_leaf_nodes=7, l2_regularization=1.0, random_state=17).fit(xhist, yhist)
            def recursive(hist: np.ndarray, n: int) -> np.ndarray:
                h = list(hist)
                out = []
                for _ in range(n):
                    feat = np.array([[h[-1], h[-2], h[-season] if len(h) >= season else h[-1]]])
                    v = float(gb.predict(feat)[0]); out.append(v); h.append(v)
                return np.asarray(out)
            val_forecast = recursive(train, len(validation))
            def recursive_model(estimator, hist: np.ndarray, n: int) -> np.ndarray:
                h = list(hist); out = []
                for _ in range(n):
                    feat = [[h[-1], h[-2], h[-season] if len(h) >= season else h[-1]]]
                    v = float(estimator.predict(feat)[0]); out.append(v); h.append(v)
                return np.asarray(out)
            candidates["gradient_boosted_lags"] = (val_forecast, recursive_model(gb_holdout, history, len(holdout)))
    except Exception:
        pass
    baseline_val, baseline_test = _metrics(validation, base_val), _metrics(holdout, base_test)
    evals = {"seasonal_naive": {"validation": baseline_val, "holdout": baseline_test}}
    eligible = []
    for name, (vp, hp) in candidates.items():
        vm, hm = _metrics(validation, vp), _metrics(holdout, hp)
        evals[name] = {"validation": vm, "holdout": hm}
        if vm["mae_mbps"] < baseline_val["mae_mbps"] and vm["rmse_mbps"] < baseline_val["rmse_mbps"] and hm["mae_mbps"] < baseline_test["mae_mbps"] and hm["rmse_mbps"] <= baseline_test["rmse_mbps"] * 1.05:
            eligible.append(name)
    selected = min(eligible, key=lambda k: evals[k]["holdout"]["mae_mbps"]) if eligible else "seasonal_naive"
    if selected == "seasonal_naive":
        pred = naive(data, horizon, baseline_period)
    elif selected == "holt_winters":
        try:
            m = ExponentialSmoothing(data, trend="add", seasonal="add", seasonal_periods=season, initialization_method="estimated").fit(optimized=True)
            pred = m.forecast(horizon)
        except Exception:
            selected = "seasonal_naive"; pred = naive(data, horizon, baseline_period)
    else:
        # Refit deterministic lag regressor on all observed history and forecast recursively.
        x, y = _lags(data, 0, len(data), season)
        gb = HistGradientBoostingRegressor(max_iter=100, max_leaf_nodes=7, l2_regularization=1.0, random_state=17).fit(x, y)
        hist = list(data); vals = []
        for _ in range(horizon):
            v = float(gb.predict([[hist[-1], hist[-2], hist[-season] if len(hist) >= season else hist[-1]]])[0]); vals.append(v); hist.append(v)
        pred = np.asarray(vals)
    return {"selected_model": selected, "baseline_period_hours": baseline_period, "selection_reason": "Selected using the predeclared validation/holdout rule." if eligible else f"No candidate passed the predeclared rule; {baseline_period}-hour seasonal-naive baseline recommended.",
            "evaluations": evals, "holdout_actual_mbps": holdout.tolist(), "holdout_forecast_mbps": base_test.tolist() if selected == "seasonal_naive" else candidates[selected][1].tolist(), "forecast_mbps": np.maximum(pred, 0).tolist(), "split_sizes": [len(train), len(validation), len(holdout)]}


def capacity(points: list[dict[str, Any]], capacity_mbps: float, headroom: float) -> dict[str, Any]:
    if capacity_mbps <= 0 or not 0 <= headroom < 1:
        raise ValueError("Capacity must be positive and headroom must be in [0, 1).")
    threshold = capacity_mbps * (1 - headroom)
    risky = [p for p in points if float(p["traffic_mbps"]) >= threshold]
    periods = []
    for p in risky:
        t = pd.Timestamp(p["timestamp"])
        if not periods or t - pd.Timestamp(periods[-1]["end"]) > pd.Timedelta(hours=1):
            periods.append({"start": t.isoformat(), "end": t.isoformat(), "peak_mbps": float(p["traffic_mbps"])})
        else:
            periods[-1]["end"] = t.isoformat(); periods[-1]["peak_mbps"] = max(periods[-1]["peak_mbps"], float(p["traffic_mbps"]))
    for period in periods:
        duration = (pd.Timestamp(period["end"]) - pd.Timestamp(period["start"])).total_seconds() / 3600
        period["duration_hours"] = duration
        period["required_capacity_mbps_estimate"] = round(period["peak_mbps"] / (1 - headroom), 2)
    return {"capacity_mbps": capacity_mbps, "headroom_fraction": headroom, "threshold_mbps": threshold, "risk_periods": periods,
            "assumption": "Forecast traffic is representative; configured headroom is reserved. Rough estimate only; for human review."}


def pseudonymize(mac: str, salt: str) -> str:
    return hashlib.sha256((salt + mac.strip().lower()).encode()).hexdigest()


def validate_device_csv(content: bytes) -> tuple[pd.DataFrame, dict[str, Any]]:
    try: raw = pd.read_csv(io.BytesIO(content))
    except Exception as exc: raise HTTPException(400, "Could not read controller CSV.") from exc
    missing = DEVICE_REQUIRED - set(raw.columns)
    if missing: raise HTTPException(400, f"Missing controller export columns: {', '.join(sorted(missing))}")
    # Explicitly reject identifying columns: the app does not accept device-level records.
    forbidden = {c for c in raw.columns if c.strip().lower() in {"mac", "mac_address", "name", "ip", "ip_address", "device_name"}}
    if forbidden: raise HTTPException(422, "Device-level identifiers are not accepted. Export aggregate counts only.")
    raw["timestamp"] = pd.to_datetime(raw.timestamp, errors="coerce", utc=True)
    raw["device_count"] = pd.to_numeric(raw.device_count, errors="coerce")
    raw["traffic_mbps"] = pd.to_numeric(raw.traffic_mbps, errors="coerce")
    bad_time = int(raw.timestamp.isna().sum()); bad_num = int((raw.device_count.isna() | raw.traffic_mbps.isna()).sum())
    negative = int(((raw.device_count < 0) | (raw.traffic_mbps < 0)).fillna(False).sum())
    valid = raw.dropna(subset=["timestamp", "ap_or_building", "device_count", "traffic_mbps"])[list(DEVICE_REQUIRED)].copy()
    valid = valid[(valid.device_count >= 0) & (valid.traffic_mbps >= 0)]
    dup = int(valid.duplicated(["timestamp", "ap_or_building"]).sum())
    valid = valid.drop_duplicates(["timestamp", "ap_or_building"], keep="first")
    report = {"rows_read": len(raw), "invalid_timestamps": bad_time, "non_numeric_values": bad_num,
              "negative_values": negative, "duplicates": dup, "rows_accepted": len(valid),
              "date_range": [valid.timestamp.min().isoformat(), valid.timestamp.max().isoformat()] if len(valid) else None}
    if not len(valid) or bad_time or bad_num or negative or dup:
        raise HTTPException(422, detail={"message": "Controller export rejected. Correct invalid or duplicate aggregate rows.", "validation": report})
    return valid.sort_values(["ap_or_building", "timestamp"]), report


def token_for(email: str, role: str) -> str:
    secret = os.getenv("JWT_SECRET", "local-development-secret-change-me")
    return jwt.encode({"sub": email, "role": role, "exp": datetime.now(timezone.utc) + timedelta(hours=8)}, secret, algorithm="HS256")
