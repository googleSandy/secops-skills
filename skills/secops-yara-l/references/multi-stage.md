# YARA-L 2.0: Multi-Stage Queries

Multi-stage queries are **search/dashboard only** — not supported in detection rules.
They allow results from one query stage to feed into another, enabling baseline comparisons,
complex correlations, and behavioral analytics.

Sources:
- https://docs.cloud.google.com/chronicle/docs/investigation/multi-stage-yaral
- https://docs.cloud.google.com/chronicle/docs/investigation/yara-l-2-0-metrics-search

---

## Syntax

```yara
// Named stages MUST be defined before the root stage
stage <stage_name> {
  // standard YARA-L query (events, match, outcome, etc.)
}

// Root stage — processed last, references named stages via $stage_name.variable
<root stage query without 'stage' keyword>
```

**Structural rules:**
- 1 root stage (required, no `stage` wrapper)
- Max 4 named stages
- Named stages must appear before the root stage in the file
- Each stage can reference stages defined before it
- Max 4 non-data-table joins across all stages
- Access stage output: `$stage_name.variable_name`
- Access window timestamps: `$stage_name.window_start`, `$stage_name.window_end`

---

## Example: Baseline vs Recent Comparison

Establishes a daily bytes baseline, then identifies spikes in recent traffic.

```yara
// Stage 1: compute daily byte totals per source/target pair
stage daily_stats {
  metadata.event_type = "NETWORK_CONNECTION"
  $source = principal.hostname
  $target = target.ip
  $source != ""
  $target != ""
  match:
    $source, $target by day
  outcome:
    $exchanged_bytes = sum(network.sent_bytes + network.received_bytes)
}

// Root stage: find pairs where today's bytes >> baseline average
$daily_stats.source = $source
$daily_stats.target = $target
$baseline_avg = avg($daily_stats.exchanged_bytes)

match:
  $source, $target

outcome:
  $current_bytes = max($daily_stats.exchanged_bytes)
  $spike_ratio   = math.round($current_bytes / $baseline_avg, 2)

condition:
  $spike_ratio > 3.0
```

---

## Example: Multi-Stage with Events and Stage Output

```yara
// Stage: count failed logins per user per hour
stage hourly_fails {
  metadata.event_type    = "USER_LOGIN"
  security_result.action = "FAIL"
  $user = principal.user.userid
  match:
    $user by 1h
  outcome:
    $fail_count = count(metadata.id)
}

// Root: find users with fail count spikes today
$hourly_fails.user    = $user
$high_fail_hour       = $hourly_fails.fail_count

match:
  $user

outcome:
  $max_hourly_fails = max($high_fail_hour)
  $total_fail_hours = count_distinct($hourly_fails.window_start)

condition:
  $max_hourly_fails > 20
```

---

## When to Use Multi-Stage vs Statistical Search

**Start with a statistical search** (single stage with `match:` and `outcome:`). Multi-stage adds
complexity — only escalate when a statistical search genuinely isn't sufficient.

| Use statistical search when | Use multi-stage when |
|---|---|
| Aggregating events into a summary | Comparing a summary against itself (stat of a stat) |
| Counting, summing, averaging events | Building a baseline then checking recent vs baseline |
| Simple group-by with threshold | Needing output of one query as input to another |
| One level of aggregation | Z-score, percentile, or anomaly detection patterns |

**Tip from community:** After building a multi-stage query, look back — many can be collapsed
into a more efficient statistical search. If your root stage could be merged into one of the
named stages, simplify it.

---

## Z-Score Anomaly Detection Pattern

Detects statistical outliers across source/target pairs. Standard deviation measures how far
a data point is from the mean. Assumes roughly normal distribution.

```yara
// Stage 1: hourly byte totals per IP pair
stage hourly_stats {
  metadata.event_type = "NETWORK_CONNECTION"
  net.ip_in_range_cidr(principal.ip, "10.128.0.0/16")
  not net.ip_in_range_cidr(target.ip, "10.128.0.0/16")
  not target.ip = "::1"
  $principal_ip = principal.ip
  $target_ip = target.ip
  match:
    $principal_ip, $target_ip by 1h
  outcome:
    $exchanged_bytes = sum(network.sent_bytes + network.received_bytes)
    $event_count     = count(metadata.id)
}

// Stage 2: compute mean and stddev across all hours
stage aggregate_stats {
  $src = $hourly_stats.principal_ip
  $dst = $hourly_stats.target_ip
  match:
    $src, $dst
  outcome:
    $mean   = avg($hourly_stats.exchanged_bytes)
    $stddev = stddev($hourly_stats.exchanged_bytes)
}

// Stage 3: compute Z-score per hour
stage z_score {
  $src = $aggregate_stats.src
  $dst = $aggregate_stats.dst
  $h_src = $hourly_stats.principal_ip
  $h_dst = $hourly_stats.target_ip
  $src = $h_src
  $dst = $h_dst
  match:
    $src, $dst, $hourly_stats.window_start
  outcome:
    $z = math.round(
      ($hourly_stats.exchanged_bytes - $aggregate_stats.mean) / $aggregate_stats.stddev,
      2
    )
    $bytes = max($hourly_stats.exchanged_bytes)
}

// Root stage: surface high Z-scores
$z_src = $z_score.src
$z_dst = $z_score.dst
$zscore = $z_score.z

match:
  $z_src, $z_dst

outcome:
  $max_z = max($zscore)

condition:
  $max_z > 3.0
```

**Limitation:** Z-score assumes a normal distribution. If your data is highly bursty,
consider median absolute deviation (MAD) instead.

---

## Tumbling Window: Frequency Analysis Pattern

`by DAY` (tumbling) creates a `time_bucket` column — events are strictly non-overlapping.

```yara
// Count IP pairs by day, classify by volume
metadata.event_type = "NETWORK_CONNECTION"
net.ip_in_range_cidr(principal.ip, "10.128.0.0/16")
not net.ip_in_range_cidr(target.ip, "10.128.0.0/16")
$principal_ip = principal.ip
$target_ip    = target.ip

match:
  $principal_ip, $target_ip by day    // creates time_bucket column

outcome:
  $traffic_light = if(count(metadata.id) < 50, "Green",
                      if(count(metadata.id) > 100, "Red", "Yellow"))
  $count = count(metadata.id)

order:
  $count desc
```

The `time_bucket` column appears automatically in results when using `by <granularity>`.
To reference it in a subsequent stage: `$stage_name.window_start` / `$stage_name.window_end`.

---

## Median Absolute Deviation (MAD) Pattern

MAD is more robust than Z-score for non-normal (bursty) security data. It uses the
**median** instead of the mean, so outliers don't distort the baseline.

**When to use MAD over Z-score:** When your data doesn't follow a normal distribution
(most security telemetry). Z-score is sensitive to outliers because it uses the mean
and standard deviation, which are both skewed by extreme values.

**Formula:** `MAD = median(|xi - median(X)|)`

**Robust Z-score formula:** `(value - median) / (MAD × 1.4826)`
The 1.4826 scaling factor makes MAD comparable to standard deviation assuming normal data.

```yara
// Stage 0: hourly byte totals per IP pair
stage hourly_stats {
  metadata.event_type = "NETWORK_CONNECTION"
  net.ip_in_range_cidr(target.ip, "10.128.0.0/16")
  not net.ip_in_range_cidr(target.ip, "10.128.15.193/32")  // exclude self
  network.sent_bytes > 0
  $ip     = principal.ip
  $target = target.ip
  match:
    $ip, $target by hour
  outcome:
    $total_bytes_sent = sum(cast.as_int(network.sent_bytes))
    $count            = count(network.sent_bytes)
}

// Stage 1: median bytes per IP pair across all hourly buckets
stage agg_stats {
  $ip     = $hourly_stats.ip
  $target = $hourly_stats.target
  match:
    $ip, $target
  outcome:
    $median_bytes_sent = window.median($hourly_stats.total_bytes_sent, false)
}

// Stage 2: absolute deviation for each hourly bucket
stage deviations {
  $hourly_stats.ip     = $agg_stats.ip
  $hourly_stats.target = $agg_stats.target
  $ip     = $hourly_stats.ip
  $target = $hourly_stats.target
  $bucket = $hourly_stats.window_start
  match:
    $ip, $target, $bucket
  outcome:
    $abs_deviation    = max(math.abs($hourly_stats.total_bytes_sent - $agg_stats.median_bytes_sent))
    $total_bytes_sent = max($hourly_stats.total_bytes_sent)
    $median           = max($agg_stats.median_bytes_sent)
}

// Stage 3: MAD = median of absolute deviations
stage median_ad {
  $ip     = $deviations.ip
  $target = $deviations.target
  match:
    $ip, $target
  outcome:
    $mad = window.median($deviations.abs_deviation, false)
}

// Root stage: compute Robust Z-score and flag outliers
$hourly_stats.ip     = $agg_stats.ip
$hourly_stats.target = $agg_stats.target
$hourly_stats.ip     = $deviations.ip
$hourly_stats.target = $deviations.target
$hourly_stats.ip     = $median_ad.ip
$hourly_stats.target = $median_ad.target
$ip     = $hourly_stats.ip
$target = $hourly_stats.target
$bucket = timestamp.get_timestamp($hourly_stats.window_start)

match:
  $ip, $target, $bucket

outcome:
  $total_bytes_sent = max($hourly_stats.total_bytes_sent)
  $median_bytes     = max($agg_stats.median_bytes_sent)
  $mad_value        = max($median_ad.mad)

  // Robust Z-score: number of "standard deviations" from median, robust to outliers
  $robust_zscore    = max(($hourly_stats.total_bytes_sent - $agg_stats.median_bytes_sent)
                          / ($median_ad.mad * 1.4826))

  // Classify outliers by threshold
  $outlier_level    = if($robust_zscore > 3.0, "Extreme",
                       if($robust_zscore > 2.0, "Alert",
                        if($robust_zscore > 1.0, "Warning", "Normal")))

condition:
  $outlier_level != "Normal"
```

**Outlier thresholds (starting points — tune per environment):**
- `> 3.0` — Extreme outlier (rare, high-confidence anomaly)
- `> 2.0` — Alert (investigate)
- `> 1.0` — Warning (monitor)

**Pro tip:** Start with a single known IP pair to validate the logic before expanding to broader netblocks.

---

## Metrics Functions (Behavioral Analytics)

Built-in precomputed metrics for behavioral analysis in search queries.
These avoid scanning raw events for common aggregations.

### Syntax

```yara
metrics.<metric_name>(
    entity:  "udm.field.path",    // which UDM field identifies the entity
    value:   $placeholder,        // the specific entity value
    period:  "1d",                // "1h" or "1d"
    window:  "30d",               // aggregation window
    operation: "max"              // max, min, sum, avg, count
)
```

### Period / Window Combinations

| period | window |
|---|---|
| `"1h"` | `"today"` |
| `"1d"` | `"30d"` |

**Note:** Hourly metrics (`period: "1h"`) can only be used in queries that also include daily metrics.
Daily metric data available by 6:00 UTC each day (previous day).

### Available Metrics

| Metric | Measures |
|---|---|
| `metrics.network_bytes_outbound` | Bytes sent per entity |
| `metrics.network_bytes_inbound` | Bytes received per entity |
| `metrics.network_bytes_total` | Total bytes per entity |
| `metrics.auth_attempts_success` | Successful auth count |
| `metrics.auth_attempts_fail` | Failed auth count |
| `metrics.auth_attempts_total` | Total auth attempts |
| `metrics.dns_queries_total` | DNS query count |
| `metrics.http_queries_total` | HTTP request count |
| `metrics.file_executions_total` | File execution count |

### Example: Detect Anomalous Data Transfer

```yara
// Find IPs sending more bytes than their 30-day max baseline
metadata.event_type = "NETWORK_CONNECTION"
$ip = principal.ip
$bytes_today = network.sent_bytes

$baseline_max = metrics.network_bytes_outbound(
    entity:    "principal.ip",
    value:     $ip,
    period:    "1d",
    window:    "30d",
    operation: "max"
)

match:
    $ip

outcome:
    $current  = sum($bytes_today)
    $baseline = max($baseline_max)
    $ratio    = math.round($current / $baseline, 2)

condition:
    $ratio > 5.0
```

### Example: Failed Login Anomaly

```yara
metadata.event_type    = "USER_LOGIN"
security_result.action = "FAIL"
$user = principal.user.userid

$baseline_fails = metrics.auth_attempts_fail(
    entity:    "principal.user.userid",
    value:     $user,
    period:    "1d",
    window:    "30d",
    operation: "avg"
)

match:
    $user

outcome:
    $today_fails = count(metadata.id)
    $baseline    = max($baseline_fails)
    $anomaly     = if($today_fails > $baseline * 3, true, false)

condition:
    $anomaly = true
```
