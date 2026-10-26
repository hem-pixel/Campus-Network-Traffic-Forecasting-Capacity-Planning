# Campus Network Traffic Forecasting and Capacity Planning

Decision support for campus network administrators. The application never connects to or changes network equipment. Traffic data is accepted only from administrator supplied approved exports. Synthetic demo figures are visibly marked and cannot be exported.

## Architecture and security

- `backend/app` is a FastAPI service; `frontend` is a React/TypeScript SPA; Compose provisions PostgreSQL and a worker profile. SQLite is the default local database.
- Persisted records: users (`Administrator`, `Planner`, `Viewer`), dataset versions and validated rows, controller aggregate imports, and audit events. Dataset versions retain source file checksum and validation summary. Capacity and alert form values are not yet persisted.
- Passwords are Argon2 hashes. Login attempts are throttled. Session tokens are signed and expire. Password-reset email delivery is not configured; the UI directs users to an administrator. Production must set a private `JWT_SECRET` and approved mail transport before enabling account recovery or email alerts.
- Authorization is enforced at the API boundary. Viewer is read-only; only Administrator/Planner upload; Administrator owns user management. Per-device access is admin-only and audited. This app does not persist raw MAC, name, IP, destinations, or app usage. The aggregate controller import accepts only timestamp, AP/building, device count and Mbps.
- Audit events record uploads, exports, aggregate-device access and user-role changes. Export names, user and timestamp are captured. Retention controls and database/file retention enforcement remain to be implemented.
- Forecast selection uses chronological 70/15/15 train/validation/holdout splits. Seasonal naive, Holt-Winters and gradient-boosted lag regression share the same splits. A candidate must beat baseline validation MAE and RMSE, then have lower holdout MAE with RMSE at most 5% above baseline, or baseline is recommended. All computed outputs are deterministic for a given file and configuration.
- Capacity advice is an estimate: `T = C * (1 - h)` and `required_capacity = peak / (1 - h)`. It is explicitly for human review and makes no guarantee of congestion prevention or savings.

## Quick start

Requires Python 3.11+ and Node 20+. For local development:

```sh
cd backend
python -m venv .venv
# activate the environment, then:
pip install -e .
uvicorn app.main:app --reload
```

In another terminal:

```sh
cd frontend
npm install
npm run dev
```

Set `VITE_API_URL` if the API is not at `http://localhost:8000`. Demo mode works without a backend. `docker compose up --build` provisions the API, PostgreSQL, frontend and worker. Set `JWT_SECRET` before using authentication outside local development. The current worker is a safe execution scaffold; model runs currently execute synchronously in the API.

## User guide

1. Explore **Try the demo** to view visibly synthetic history, forecast, capacity threshold and risk periods. Demo uploads and exports are disabled.
2. Sign in, then upload an approved CSV with `timestamp,traffic_mbps,segment_id` and optional `direction`. Use ISO-8601 timestamps, nonnegative numeric Mbps and one row per segment/time/direction. The validator reports row counts, invalid timestamps, nonnumeric/negative traffic, duplicates, missing intervals and date range. Rejected rows are not silently used.
3. Review history and forecast evaluation. Configure link capacity and desired headroom before reading risk periods or recommendations. All values include units and assumptions.
4. Configure users as permitted by role. Review audit records for uploads and exports. Public sign-up creates Viewers. To provision the first Administrator, set both `BOOTSTRAP_ADMIN_EMAIL` and a high-entropy `BOOTSTRAP_ADMIN_SECRET`; submit that secret as `bootstrap_token` to `/api/auth/signup` for the configured address. Do not expose the bootstrap secret in the public UI.

Device counts use the confirmed aggregate controller-export columns `timestamp,ap_or_building,device_count,traffic_mbps`. The import rejects common device-identifier columns and persists only these four fields. A measurement older than 24 hours is flagged stale; treat that as a default freshness limit until the controller refresh cadence is confirmed.

## Demo walkthrough

Open the public landing page, activate **Try the demo**, and verify every page/chart carries `DEMO DATA - SYNTHETIC`. Inspect traffic history, forecast vs actual, the capacity threshold, grouped risk periods and synthetic device counts per AP. Uploads and exports are unavailable in demo mode. Return to landing and use sign-in to access the authenticated workspace.

## Tests and verification

- Backend: `python -m pytest tests -q` — **13 passed** (2026-10-26). Four statsmodels convergence warnings occurred during forecast reproducibility checks; deterministic output assertions passed.
- Frontend production build: `npm run build` — **passed** (2026-10-26). Vite reported a 770 kB JavaScript chunk advisory.
- Playwright: `npm run test:e2e` — **2 passed** (2026-10-26). Start the Vite server first with `npm run dev`; install the browser once with `node ./node_modules/playwright/cli.js install chromium`.

## Current implementation boundaries

- Forecast model execution is synchronous in the API. The Compose worker is only a scaffold and does not yet consume queued work.
- The authenticated traffic-history chart reads uploaded data. The forecast and capacity planning screens still need full authenticated forecast-result wiring for their charts and risk-period panels; their synthetic examples are labeled, and real values remain “to be recorded.”
- Device aggregate CSV import and API calculations are implemented. The UI shows aggregate rows and measurement freshness; per-device records are not accepted.
- Alert rules/email delivery, password-reset email delivery, persistent workspace settings/retention enforcement, and PDF inclusion of capacity configuration are not configured. The UI surfaces setup status; configure approved mail and retention services before relying on those workflows.
- There is no production deployment hardening, operational monitoring, or security certification.

## Limitations

This is an initial implementation scaffold, not a production security certification. Configure TLS, secret management, mail transport, backups, retention jobs, monitoring, and an approved identity policy before deployment. Do not upload personal data or unapproved exports. The API does not make changes to network equipment.

## Synthetic sample datasets

- `sample_full_synthetic_dataset.csv` contains 28 days of hourly, two-segment synthetic traffic and aggregate device counts. Upload it once from **Overview → Upload data** to populate traffic KPIs, then again from **Connected devices → Upload controller export** to populate device KPIs.
- `sample_traffic_synthetic.csv` and `sample_controller_devices_synthetic.csv` provide the same information in separate import formats.
- These examples are synthetic and are not campus measurements. For weekly seasonality, use several complete weeks of approved hourly data; the forecasting baseline compares 24-hour and 168-hour patterns when enough observations are available.
