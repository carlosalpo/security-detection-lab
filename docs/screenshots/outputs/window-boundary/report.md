# Security Detection Lab — replay report

Signals: **signals_detected** · expectation check: **passed**

Scope: offline replay of supplied normalized events. No attack execution, live collection, SIEM integration, network scan or response action. Signals are review leads, not proof of compromise.

Input records: 3 · unique events: 3 · exact duplicates removed: 0 · alerts: 1

## Rule execution

| Rule | Enabled | Window seconds | Threshold | Qualifying triggers | Emitted | Suppressed |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| auth\-failure\-burst | True | 300 | 2 | 1 | 1 | 0 |
| denied\-port\-fanout | True | 60 | 5 | 0 | 0 | 0 |
| multi\-account\-failures | True | 300 | 5 | 0 | 0 | 0 |
| success\-after\-failures | True | 300 | 3 | 0 | 0 | 0 |

## Alerts

### auth-failure-burst — 2026-10-29T12:05:00Z

Repeated authentication failures for one source, account and service\.

Trigger: `edge-inclusive` · severity: medium · failure_count: 2 (threshold 2)

```json
{
  "evidence_ids": [
    "edge-first",
    "edge-inclusive"
  ],
  "group": {
    "service": "vpn-lab",
    "src_ip": "192.0.2.10",
    "user": "alice"
  },
  "window_start": "2026-10-29T12:00:00Z"
}
```


## Expected-alert comparison

```json
{
  "actual_alerts": 1,
  "evidence_mismatches": [],
  "expected_alerts": 1,
  "matched_alerts": 1,
  "missing_alerts": [],
  "scenario": "window-boundary",
  "status": "passed",
  "unexpected_alerts": []
}
```

## Timing and interpretation

- Rolling windows include the lower boundary. Events are sorted by UTC time and ID; ID order is a deterministic tie-break, not proof of ordering within a second.
- Success-after-failures uses only failures strictly before the success and strictly after the previous success for that key. A success resets that sequence even below threshold.
- Each rule/key suppresses qualifying triggers until one window has elapsed since its last emitted alert. A trigger exactly at the cooldown boundary may emit; suppressed triggers do not extend it.
- Counts refer to supplied unique event records. Distinct-account/port rules use unique values inside a window; exact duplicate IDs never inflate thresholds.
- Expected checks compare rule, triggering event and complete evidence ID sets. Missing, unexpected and evidence-mismatched alerts fail separately. No expectation means not evaluated.
- Authentication signals may reflect retries, shared source addresses or maintenance. Denied port fanout may reflect authorized diagnostics; it does not establish that ports are open.
- Thresholds and severities are lab choices. Native log normalization, data completeness, tenant identity, production tuning and response decisions require separate engineering.
- Input and output are not anonymized. The hash manifest is unsigned.
