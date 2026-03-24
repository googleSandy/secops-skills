# SecOps SIEM Search: Functions Reference

## Aggregate Functions

Used in the `outcome:` section of stats and join queries.

| Function | Param type | Return | Purpose |
|---|---|---|---|
| `count(field)` | STRING | NUMBER | Count rows in group (field required) |
| `count_distinct(field)` | STRING | NUMBER | Count distinct values in group |
| `sum(field)` | NUMBER | NUMBER | Sum a numeric field |
| `avg(field)` | NUMBER | NUMBER | Average of numeric field |
| `min(field)` | NUMBER | NUMBER | Minimum value |
| `max(field)` | NUMBER | NUMBER | Maximum value |
| `stddev(field)` | NUMBER | NUMBER | Standard deviation |
| `earliest(timestamp_field)` | TIMESTAMP | TIMESTAMP | Earliest timestamp in group |
| `latest(timestamp_field)` | TIMESTAMP | TIMESTAMP | Latest timestamp in group |
| `array(field)` | STRING | LIST | Up to 25 random values |
| `array_distinct(field)` | STRING | LIST | Up to 25 distinct values |
| `math.round(value, digits)` | NUMBER, NUMBER | NUMBER | Round to N decimal places |
| `if(condition, a, b)` | BOOL, ANY, ANY | ANY | Conditional value |
| `strings.shannon_entropy(field)` | STRING | NUMBER | Shannon entropy of a string |

### Examples

```
// Count + distinct count
$logins = count(metadata.id)
$distinct_users = count_distinct(principal.user.userid)

// Statistical summary
$avg_bytes = avg(network.sent_bytes)
$stddev_bytes = stddev(network.sent_bytes)
$max_bytes = max(network.sent_bytes)

// Timestamps
$first_seen = earliest(metadata.event_timestamp)
$last_seen = latest(metadata.event_timestamp)

// Arrays
$user_list = array_distinct(principal.user.userid)

// Conditional
$is_malicious = if(security_result.threat_verdict = "MALICIOUS", 1, 0)
```

### Note on `window.*` prefix

Older SecOps queries may use `window.avg()`, `window.stddev()`, `window.median()` — these are detection-rule-style prefixes that work in search but are not canonical. Use the unprefixed forms (`avg()`, `stddev()`) in new queries.

`window.median()` has no direct equivalent in the canonical search functions; use `stddev()` + `avg()` for distribution analysis instead, or use `array()` to sample values.

---

## Built-in Filter Functions

Used inline in the filter section (before `match:`).

| Function | Purpose |
|---|---|
| `net.ip_in_range_cidr($ip, "10.0.0.0/8")` | True if IP is within CIDR range |
| `timestamp.get_timestamp(field.seconds, "%F")` | Format epoch seconds as string (`%F` = YYYY-MM-DD) |
| `timestamp.get_date(field.seconds, "America/Los_Angeles")` | Date string with named timezone |
| `strings.shannon_entropy(field)` | Entropy score of a string field |
| `math.round(value, digits)` | Round numeric value to N decimal places |

### Timestamp formatting examples

```
// Group by calendar date (UTC)
$date = timestamp.get_timestamp(metadata.event_timestamp.seconds, "%F")

// Group by date in specific timezone
$date = timestamp.get_date(metadata.event_timestamp.seconds, "America/New_York")

// Use in match section
match:
    $date, $hostname
```
