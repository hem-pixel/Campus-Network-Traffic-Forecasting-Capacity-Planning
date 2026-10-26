import io

import numpy as np
import pandas as pd
import pytest
from fastapi import HTTPException

from app.core import capacity, chronological_split, forecast, pseudonymize, validate_csv, validate_device_csv


def traffic_csv(rows):
    return pd.DataFrame(rows, columns=["timestamp", "traffic_mbps", "segment_id"]).to_csv(index=False).encode()


def test_csv_validation_accepts_valid_and_reports_missing_intervals():
    content = traffic_csv([["2026-01-01T00:00:00Z", 12, "link-a"], ["2026-01-01T02:00:00Z", 18, "link-a"]])
    frame, report = validate_csv(content)
    assert len(frame) == 2
    assert report["rows_read"] == 2
    assert report["missing_intervals"] == 1


@pytest.mark.parametrize("rows", [
    [["not-a-time", 10, "a"]],
    [["2026-01-01T00:00:00Z", "bad", "a"]],
    [["2026-01-01T00:00:00Z", -1, "a"]],
])
def test_csv_rejects_bad_rows(rows):
    with pytest.raises(HTTPException) as exc:
        validate_csv(traffic_csv(rows))
    assert exc.value.status_code == 422


def test_chronological_split_has_no_shuffle_or_overlap():
    values = np.arange(100)
    train, validation, holdout = chronological_split(values)
    assert (len(train), len(validation), len(holdout)) == (70, 15, 15)
    assert train[-1] < validation[0] < holdout[0]


def test_forecast_is_reproducible_and_uses_selection_rule():
    values = (500 + 100 * np.sin(np.arange(240) * 2 * np.pi / 24)).tolist()
    a = forecast(values, horizon=12)
    b = forecast(values, horizon=12)
    assert a == b
    assert len(a["forecast_mbps"]) == 12
    assert a["selected_model"] in a["evaluations"]
    assert a["selection_reason"]


def test_capacity_groups_risk_and_estimates_required_capacity():
    points = [{"timestamp": f"2026-01-01T0{i}:00:00Z", "traffic_mbps": v} for i, v in enumerate([60, 90, 95, 40])]
    result = capacity(points, 100, .15)
    assert result["threshold_mbps"] == 85
    assert len(result["risk_periods"]) == 1
    assert result["risk_periods"][0]["duration_hours"] == 1
    assert result["risk_periods"][0]["required_capacity_mbps_estimate"] == 111.76


def test_pseudonymization_is_stable_and_salted():
    assert pseudonymize("AA:BB:CC", "salt-a") == pseudonymize("aa:bb:cc", "salt-a")
    assert pseudonymize("aa:bb:cc", "salt-a") != pseudonymize("aa:bb:cc", "salt-b")


def test_controller_export_accepts_aggregates_and_discards_unknown_columns():
    frame, report = validate_device_csv(b"timestamp,ap_or_building,device_count,traffic_mbps,extra\n2026-01-01T00:00:00Z,AP-1,10,20,not-kept\n")
    assert set(frame.columns) == {"timestamp", "ap_or_building", "device_count", "traffic_mbps"}
    assert report["rows_accepted"] == 1


def test_controller_export_rejects_device_identifiers():
    with pytest.raises(HTTPException) as exc:
        validate_device_csv(b"timestamp,ap_or_building,device_count,traffic_mbps,mac\n2026-01-01T00:00:00Z,AP-1,1,2,AA:BB\n")
    assert exc.value.status_code == 422
