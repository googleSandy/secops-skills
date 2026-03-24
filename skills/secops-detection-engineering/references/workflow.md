# Detection Engineering: Rule Lifecycle & Management

Sources:
- https://docs.cloud.google.com/chronicle/docs/detection/manage-all-rules
- https://docs.cloud.google.com/chronicle/docs/detection/run-rule-live-data
- https://docs.cloud.google.com/chronicle/docs/detection/run-rule-historical-data

---

## Rule Lifecycle

```
1. Write rule in Rules Editor (YARA-L)
2. Save → auto syntax check → compilation errors shown inline
3. Run Test → validate logic on historical data (non-persistent, no alerts)
4. Retrohunt → apply to historical data (real detections, real alerts)
5. Enable Live Rule → continuous detection on incoming events
```

---

## Create a New Rule

**Navigation:** Detection > Rules & Detections > Rules Editor tab > New

1. Editor auto-populates a default rule template with a generated name
2. Write your rule in YARA-L 2.0
3. Click **Save new rule** — syntax is validated on save
4. If converting a Search query to a rule: add `nocase` to string comparisons
   (Search defaults to case-insensitive; rules do not)
5. Optionally bind rule to a data access scope via **Bind to scope**

---

## Run Test (Non-Persistent Testing)

**Button:** Run Test in the Rules Editor

- Executes rule against events in specified time range
- Results display in **Test rule results** window
- **Does NOT** persist, generate alerts, or appear in Rules Dashboard
- `suppression_window` option is **NOT applied** during test
- Successive runs may produce different results (parallel execution, minor timing differences)
- Test results may differ from retrohunt/live results due to window alignment differences

**Rule of thumb:** If test produces 0 results, check:
1. Time range covers events that should match
2. Verify data is ingested using raw log search first
3. Check event type and field name accuracy

---

## Retrohunt (Historical Detection)

**Access:** Rules Dashboard > Rules option icon (⋮) > YARA-L Retrohunt

1. Select start and end times (default: last 1 week)
2. For multi-event rules: time range **must be ≥ match window size**
3. Click Run — results stream as each parallel process completes
4. View progress in Rule Detections view for that rule
5. Cancel at any time (partial detections are retained)
6. Multiple retrohunts can be run; view history via date range links

**Important:** If rule has alerting disabled, retrohunt detections will NOT generate alerts.
To enable: create a new rule version with alerting enabled, then re-run.

**Retrohunt vs Test:**
| | Run Test | Retrohunt |
|---|---|---|
| Generates alerts | No | Yes (if alerting on) |
| Persists results | No | Yes |
| Appears in dashboard | No | Yes |
| Can cancel mid-run | Yes | Yes |

---

## Enable Live Rule (Real-Time Detection)

**Navigation:** Detection > Rules & Detections > Rules Dashboard

1. Click ⋮ Rules option icon for a rule
2. Toggle **Live Rule** to enabled
3. Rule now processes incoming events continuously
4. Click **View Rule Detections** to see live detections

**When disabled:** Rule does NOT process real-time events. Only test and retrohunt work.

**On save:** New rules are saved but NOT automatically enabled as live.
You must explicitly enable the Live Rule toggle.

---

## Rule Versions

Every save creates a new rule version. Previous versions remain accessible:
- Live detections continue using the version that was active when they were generated
- Each version can be independently enabled/disabled as a live rule

---

## Rule Quotas

View quota at top right of Rules Dashboard: **Rules capacity**

Limits apply to the number of rules that can be simultaneously enabled as live.
Check capacity before enabling large numbers of rules. Quota details are instance-specific.

---

## Set Run Frequency

**Navigation:** Rules Dashboard > rule ⋮ > Set run frequency

| Frequency | Best for |
|---|---|
| Near real-time | Single-event rules requiring fastest detection |
| 10 minutes | Multi-event rules with match window < 60m |
| 1 hour | Multi-event rules with match window 60m–24h |
| 24 hours | Rules with very long windows or low-priority detections |

Higher frequency = lower detection latency but higher resource consumption.

---

## Search for and Filter Rules

**Navigation:** Detection > Rules & Detections > Rules Dashboard

- Filter by: enabled/disabled, alerting on/off, rule type, severity
- Search by rule name or content
- Sort by detection count, last modified, name

---

## View Detections

- **Rules Dashboard:** Aggregate detection counts per rule
- **Rule Detections view:** Timeline graph + individual detections for a specific rule
- Detections include outcome variables as columns
- Click a detection to drill into matching events
