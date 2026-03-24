# YARA-L 2.0: Functions Reference

Source: https://docs.cloud.google.com/chronicle/docs/yara-l/functions

Authoritative function list — fetch live for signatures not shown here.

---

## Aggregate Functions (outcome: section)

| Function | Returns | Purpose |
|---|---|---|
| `count(field)` | int | Count rows |
| `count_distinct(field)` | int | Count distinct values |
| `sum(field)` | number | Sum |
| `avg(field)` | float | Average |
| `min(field)` | number | Minimum |
| `max(field)` | number | Maximum |
| `stddev(field)` | float | Standard deviation |
| `array(field)` | list | Up to 25 random values |
| `array_distinct(field)` | list | Up to 25 distinct values |
| `earliest(timestamp_field)` | timestamp | Earliest timestamp in group |
| `latest(timestamp_field)` | timestamp | Latest timestamp in group |

---

## Regex Functions

```yara
// Test if field matches regex (returns bool)
re.regex($e.target.url, `phishing.*page`)

// Capture a group (returns string)
$domain = re.capture($e.target.url, `https?://([^/]+)`)

// Capture all matches (returns list of strings)
$matches = re.capture_all($e.target.command_line, `(?i)(mimikatz|sekurlsa)`)

// Replace (returns string)
$clean = re.replace($e.target.url, `\?.*`, "")   // strip query string
```

---

## String Functions

| Function | Signature | Returns |
|---|---|---|
| `strings.concat` | `strings.concat(s1, s2, ...)` | string |
| `strings.contains` | `strings.contains(str, substr)` | bool |
| `strings.starts_with` | — | bool |
| `strings.ends_with` | `strings.ends_with(str, suffix)` | bool |
| `strings.to_lower` | `strings.to_lower(str)` | string |
| `strings.to_upper` | `strings.to_upper(str)` | string |
| `strings.trim` | `strings.trim(str, chars)` | string |
| `strings.ltrim` | `strings.ltrim(str, chars)` | string |
| `strings.rtrim` | `strings.rtrim(str, chars)` | string |
| `strings.split` | `strings.split(str, delim)` | list |
| `strings.coalesce` | `strings.coalesce(s1, s2, ...)` | string — first non-empty |
| `strings.reverse` | `strings.reverse(str)` | string |
| `strings.count_substrings` | `strings.count_substrings(str, substr)` | int |
| `strings.extract_domain` | `strings.extract_domain(url)` | string |
| `strings.extract_hostname` | `strings.extract_hostname(url)` | string |
| `strings.url_decode` | `strings.url_decode(url)` | string |
| `strings.from_base64` | `strings.from_base64(str)` | string |
| `strings.base64_decode` | `strings.base64_decode(str)` | string |
| `strings.from_hex` | `strings.from_hex(hex_str)` | string |
| `strings.shannon_entropy` | `strings.shannon_entropy(str)` | float — entropy score |

---

## Math Functions

| Function | Signature | Returns |
|---|---|---|
| `math.round` | `math.round(value, digits)` | number |
| `math.abs` | `math.abs(value)` | number |
| `math.ceil` | `math.ceil(value)` | int |
| `math.floor` | `math.floor(value)` | int |
| `math.sqrt` | `math.sqrt(value)` | float |
| `math.pow` | `math.pow(base, exp)` | float |
| `math.log` | `math.log(value)` | float |
| `math.random` | `math.random()` | float (0–1) |
| `math.geo_distance` | `math.geo_distance(lat1, lon1, lat2, lon2)` | float (km) |
| `math.is_increasing` | `math.is_increasing(list)` | bool |

---

## Timestamp Functions

| Function | Signature | Returns |
|---|---|---|
| `timestamp.get_timestamp` | `timestamp.get_timestamp(seconds, format)` | string — formatted date |
| `timestamp.get_date` | `timestamp.get_date(seconds, timezone)` | string — date |
| `timestamp.get_hour` | `timestamp.get_hour(seconds, timezone)` | int (0–23) |
| `timestamp.get_minute` | `timestamp.get_minute(seconds, timezone)` | int (0–59) |
| `timestamp.get_day_of_week` | `timestamp.get_day_of_week(seconds, timezone)` | int (1=Sun…7=Sat) |
| `timestamp.get_week` | `timestamp.get_week(seconds, timezone)` | int (week number) |
| `timestamp.as_unix_seconds` | `timestamp.as_unix_seconds(timestamp_field)` | int |
| `timestamp.current_seconds` | `timestamp.current_seconds()` | int — now as epoch |
| `timestamp.diff` | `timestamp.diff(end_seconds, start_seconds, unit)` | number |

**Common format strings:** `"%F"` = YYYY-MM-DD, `"%Y"` = year, `"%H"` = hour, `"%M"` = minute.

### timestamp.diff

Calculates the difference between two epoch-second values in a specified time unit.
**Argument order:** end timestamp first, start timestamp second.

```yara
// Time units: "SECOND", "MINUTE", "HOUR", "DAY", "WEEK", "MONTH", "QUARTER", "YEAR"
$diff_seconds = timestamp.diff(metadata.ingested_timestamp.seconds, metadata.event_timestamp.seconds, "SECOND")
$diff_minutes = timestamp.diff(metadata.ingested_timestamp.seconds, metadata.event_timestamp.seconds, "MINUTE")
$diff_hours   = timestamp.diff(metadata.ingested_timestamp.seconds, metadata.event_timestamp.seconds, "HOUR")
$diff_days    = timestamp.diff(metadata.ingested_timestamp.seconds, metadata.event_timestamp.seconds, "DAY")
```

**Note:** If you're unsure which timestamp is larger, wrap with `math.abs()` to avoid negatives:
```yara
$diff = math.abs(timestamp.diff(ts1.seconds, ts2.seconds, "MINUTE"))
```

**vs subtraction:** `ts1 - ts2` returns raw seconds. `timestamp.diff` returns the difference expressed
in the given unit (truncated, not rounded). Use subtraction when you need seconds; use `timestamp.diff`
when you want to express the difference in a human-readable time unit.

---

## Network Functions

```yara
net.ip_in_range_cidr($ip, "10.0.0.0/8")     // returns bool
```

---

## Hash Functions

```yara
hash.sha256($e.target.file.full_path)        // returns SHA-256 string
```

---

## Cast Functions

| Function | Returns |
|---|---|
| `cast.as_int(value)` | int |
| `cast.as_float(value)` | float |
| `cast.as_string(value)` | string |
| `cast.as_bool(value)` | bool |

---

## Array Functions

| Function | Signature | Returns |
|---|---|---|
| `arrays.index_to_str` | `arrays.index_to_str(arr, idx)` | string |
| `arrays.index_to_int` | `arrays.index_to_int(arr, idx)` | int |
| `arrays.index_to_float` | `arrays.index_to_float(arr, idx)` | float |
| `arrays.concat` | `arrays.concat(arr1, arr2)` | list |
| `arrays.join_string` | `arrays.join_string(arr, delim)` | string |
| `arrays.length` | `arrays.length(arr)` | int |
| `arrays.size` | `arrays.size(arr)` | int |
| `arrays.min` | `arrays.min(arr)` | number |
| `arrays.max` | `arrays.max(arr)` | number |

---

## Other Functions

| Function | Purpose |
|---|---|
| `if(cond, a, b)` | Conditional — returns a if cond true, else b |
| `fingerprint(field1, field2, ...)` | Deterministic hash of multiple fields |
| `group(field)` | Groups values for aggregation |
| `bytes.to_base64(bytes_field)` | Encode bytes as base64 string |
| `sample_rate(n)` | Randomly sample 1 in n events |

---

## Metrics Functions (Behavioral Analytics)

Two syntax styles exist depending on context. Named parameters — order doesn't matter.

### In Detection Rules (`outcome:` section)

```yara
outcome:
  $max_bytes = max(metrics.network_bytes_outbound(
      period:1d, window:30d,
      metric:value_sum,
      agg:max,
      principal.asset.ip:$ip
  ))
```

**Rule-specific parameters:**
- `metric:value_sum` — sum per period (bytes metrics)
- `metric:event_count` — count per period
- `metric:first_seen` — first observation
- `agg:max` / `agg:avg` — aggregation across the window
- Grouping field uses colon notation: `principal.asset.ip:$ip`

### In Search Queries (`outcome:` section)

Used in search queries for entity behavioral analytics. Named parameters — order doesn't matter.

```yara
// Max bytes sent by this IP in the last 30 days (daily granularity)
metrics.network_bytes_outbound(
    entity: "principal.ip",
    value: $e.principal.ip,
    period: "1d",
    window: "30d",
    operation: "max"
)

// Count of failed logins per user over 7 days
metrics.auth_attempts_fail(
    entity: "principal.user.userid",
    value: $user,
    period: "1d",
    window: "7d",
    operation: "sum"
)
```

**Parameters:**
- `entity` — UDM field path identifying the entity
- `value` — the specific entity value (variable or literal)
- `period` — granularity: `"1h"` or `"1d"` (hourly metrics require daily to be present)
- `window` — aggregation range (valid values depend on period)
- `operation` — `"max"`, `"min"`, `"sum"`, `"avg"`, `"count"`

**Note:** Metric data for the previous day is available by 6:00 UTC. Daily metric windows cover
up to 30d. Hourly metrics can only be used alongside daily metrics in the same query.

See `multi-stage.md` for additional metrics usage patterns.
