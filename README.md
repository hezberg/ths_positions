# ths-position

Position query for **THS Investment Ledger** (同花顺投资账本, Android app). Python library + CLI in a single file.

Login with account credentials or SMS code, then pull bound broker accounts and per-account position snapshots (cash balance, market value, daily P&L, holdings detail). **Read-only** — no write operations.

> ⚠️ Unofficial third-party client. For learning and exporting **your own** data only. APIs may break with any app update. Do not use with other people's accounts or for high-frequency polling.

## Install

```bash
pip install requests cryptography
```

Requires Python ≥ 3.8.

## CLI

```bash
# Login with credentials (session persisted automatically)
python3 ths_position.py login -u <username> -p <password>

# List bound broker accounts (source of qsid / zjzh)
python3 ths_position.py accounts

# Positions for all accounts
python3 ths_position.py positions

# Human-readable table instead of JSON
python3 ths_position.py positions --format text

# Positions for one account
python3 ths_position.py positions --qsid <qsid> --zjzh <fund account>

# Alternative: SMS code login
python3 ths_position.py sms-send --phone 138xxxxxxxx
python3 ths_position.py sms-login --phone 138xxxx --code 123456

# Offline self-test
python3 ths_position.py selftest
```

All output is JSON.

## Python API

```python
from ths_position import ThsPositionClient

c = ThsPositionClient()
c.login_password("<username>", "<password>")   # long-lived session

for acc in c.list_accounts():
    snap = c.get_positions(acc["qsid"], acc["zjzh"], margin=acc["rzrq"])
    pos = c.normalize_snapshot(snap)
    print(acc["qsmc"], pos["cash_balance"], pos["market_value"], len(pos["positions"]))
```

`get_positions` returns the raw server snapshot. Use `normalize_snapshot()` (also applied by the CLI `positions` command) for a stable, agent-friendly shape:

```json
{"cash_balance": 123456.78, "market_value": 234567.89, "daily_pnl": 0.0,
 "positions": [{"code": "000000", "name": "<stock>", "quantity": 100,
           "avg_cost": 10.0, "last_price": 10.5, "market_value": 1050.0,
           "weight": 0.05, "pnl": 50.0, "pnl_pct": 5.0,
           "industry": "...", "hold_days": 1}],
 "last_sync": "2026-09-18T03:26:22.309000+00:00"}
```

## Session & state

State is auto-saved to `ths_position_state.json` (mode 0600) next to the script: session key, synthetic device fingerprint and login session. **The file is the device** — deleting it means the next login registers as a new device. One login lasts a long time; re-run `login` when the session expires.

## Known limitations

- Data freshness depends on the user's last in-app sync; queries never trigger a sync
- Requires network access from mainland China
- Stop using it if a captcha / risk-control prompt appears

## Acknowledgements

- [sunnysab/ths-favorite](https://github.com/sunnysab/ths-favorite) — the login flow is based on this project's implementation.

## License

MIT
