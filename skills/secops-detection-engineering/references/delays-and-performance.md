# Detection Engineering: Delays & Performance

Sources:
- https://docs.cloud.google.com/chronicle/docs/detection/detection-delays
- https://docs.cloud.google.com/chronicle/docs/detection/optimize-detection-and-reporting-performance

---

## MTTD Components (Total Detection Latency)

Mean Time to Detect = sum of three components:

```
Log creation → [Log-ingestion latency] → Data ingested
Data ingested → [Rule-processing latency] → Detection created
Detection created → [Case-acknowledgement latency] → Analyst assigned
```

### 1. Log-Ingestion Latency

Time from security event occurring (`metadata.event_timestamp`) to ingestion
(`metadata.ingested_timestamp`).

**Contributing factors:**
- Collector/forwarder backlogs or network throttling
- Parser delays in UDM normalization

**Monitor with:**
```yara
// Compare ingested time vs event time to detect lag
metadata.product_name = "YOUR_LOG_SOURCE"
outcome:
  $lag_seconds = max(metadata.ingested_timestamp.seconds - metadata.event_timestamp.seconds)
order:
  $lag_seconds desc
```

### 2. Rule-Processing Latency

Time from data ingestion to detection creation.

**Contributing factors:**
- **Run frequency**: near real-time < 10m < 1h < 24h
- **Rule type**: multi-event rules require full match window to complete
- **Rule complexity**: composite rules that depend on other detections add cumulative delay
- Non-existence conditions add ~1 hour delay for late data

**Optimization rule (deploy to test environment to baseline):**
```yara
rule rule_processing_latency_monitor {
  meta:
    description = "Identifies detections where ingestion-to-detection delta exceeds threshold"
    severity    = "LOW"
  events:
    $e.metadata.event_type != ""
    $e.metadata.ingested_timestamp.seconds > 0
    $lag = $e.metadata.ingested_timestamp.seconds - $e.metadata.event_timestamp.seconds
    $lag > 300    // flag events with >5 min ingestion lag
  outcome:
    $log_type     = array_distinct($e.metadata.log_type)
    $avg_lag      = math.round(avg($lag), 0)
    $max_lag      = max($lag)
  condition:
    $e
}
```

### 3. Case-Acknowledgement Latency

Time from detection to analyst assignment (SOAR component only — not relevant for SIEM standalone).

---

## Expected vs Unpredicted Delays

### Expected (controllable)

| Factor | Impact | Fix |
|---|---|---|
| Run frequency | Lower frequency = higher latency | Increase frequency |
| Match window size | Longer window = longer wait for complete correlation | Minimize window |
| Rule type | Multi-event > single-event | Use single-event where possible |
| Composite rules | Inherit delays from upstream rules | Accept or parallelize |
| Non-existence condition | +1h delay for late data | Design match window accordingly |

### Unpredicted (transient)

- Late-arriving event data from log sources
- Transient pipeline slowness
- Re-enrichment of UDM events after enrichment data updates
- Data processing backlogs

---

## Tips to Reduce Detection Latency

1. **Use the highest feasible run frequency** for each rule type:
   - Single-event → Near real-time
   - Multi-event window < 60m → 10 minutes
   - Multi-event window ≥ 60m → 1 hour or 24 hours

2. **Minimize match window duration** — use the smallest window that still captures the threat

3. **Use single-event rules** for time-sensitive detections where possible

4. **Add specific filters early** — narrow to `metadata.event_type` and `metadata.log_type`
   before broader conditions to reduce events processed per run

5. **Avoid non-existence conditions** on latency-sensitive rules (adds ~1h delay)

6. **Monitor ingestion lag** — if `event_timestamp` is far behind `ingested_timestamp`
   for a log source, that's a collector or parser issue, not a rule issue

---

## Analyze a Rule's Detection Delays

To diagnose why a specific rule has detection lag:

1. Check the rule's **run frequency** setting
2. Check the **match window** size — the rule cannot fire until the window completes
3. Verify the **log source ingestion lag** (collector health)
4. Look at the **rule type**: single-event, multi-event, composite
5. Check for **non-existence conditions** (add `not $e2` → +1h)
6. Review the **detection generation method** used by the rule

**Expected minimum latency formula (approximate):**
`ingestion_lag + run_frequency + match_window + enrichment_time`
