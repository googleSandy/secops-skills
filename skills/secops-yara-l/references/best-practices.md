# YARA-L 2.0: Best Practices & Known Issues

Sources:
- https://docs.cloud.google.com/chronicle/docs/detection/yara-l-best-practices
- https://docs.cloud.google.com/chronicle/docs/detection/yara-l-issues

---

## Best Practices

### 1. Always Add an Event Type Filter

Without an event type filter, the rule evaluates every UDM event — expensive.

```yara
// ❌ Scans all events to check the reference list
events:
  $e.target.ip in %suspicious_ips

// ✓ Scopes to DNS events first — much faster
events:
  $e.metadata.event_type = "NETWORK_DNS"
  $e.target.ip in %suspicious_ips
```

### 2. Filter Out Zero Values on Joins

When two fields are both absent, they both default to `""` — an unintended match.

```yara
// ❌ May match on empty-string join
$e1.principal.hostname = $e2.target.hostname

// ✓ Exclude empty-string matches explicitly
$e1.principal.hostname = $e2.target.hostname
$e1.principal.hostname != ""
```

For `match` section placeholders: zero values are filtered out by default.
Set `options: allow_zero_values = true` only when you specifically need to match empty fields.

### 3. Filter Enrichment-Dependent Fields

Enriched data (geolocation, VirusTotal) may be null on newly ingested events.
Add null checks on enrichment-dependent conditions:

```yara
events:
  $e.principal.ip = $ip
  $e.principal.ip_geo_artifact.location.country_or_region != ""  // exclude un-enriched
  $e.principal.ip_geo_artifact.location.country_or_region != "United States"
```

### 4. Use Specific Filters Before Broad Ones

Put the most restrictive conditions first to minimize events evaluated:

```yara
events:
  // ✓ Indexed, specific filter first
  $e.metadata.log_type = "WINEVTLOG"
  $e.metadata.event_type = "PROCESS_LAUNCH"
  // Broader filter after
  $e.target.process.command_line = /.*mimikatz.*/
```

### 5. Prefer Placeholder Variables Over Field Comparisons

Placeholder variables are optimized for joining; direct field comparisons across
event variables may be less efficient.

```yara
// ✓ Use placeholder for join
$user = $e1.principal.user.userid
$user = $e2.principal.user.userid

// ❌ Less efficient direct comparison
$e1.principal.user.userid = $e2.principal.user.userid
```

### 6. Non-Existence Queries Need 1-Hour Delay Buffer

When detecting absence of an event (`not $e2`), the detection engine adds ~1 hour
delay to allow for late-arriving data. Design time windows accordingly:

```yara
// Looking for firewall_1 without firewall_2 in 10 minutes
// Expect detections to arrive ~70 minutes after the event window
match:
  $host over 10m after $e1

condition:
  $e1 and not $e2
```

---

## Known Issues

### Issue 1: Repeated Field Unnesting in Outcome

Repeated fields (like `target.ip`) are "unnested" — each value becomes a separate event row.
This inflates `count()` results:

```yara
// If $e has target.ip = ["1.2.3.4", "5.6.7.8"], count yields 2 not 1
outcome:
  $outbound_ip_count = count($e.target.ip)   // ❌ double-counts repeated values

// ✓ Use count_distinct or assign to placeholder first
$ip = $e.target.ip
outcome:
  $outbound_ip_count = count_distinct($ip)
```

### Issue 2: Outcome with Multiple Event Variables Compounds

If a rule has `$e1` and `$e2`, each combination of (e1, e2) creates a separate
aggregation row. `count($e1.field)` counts each e1 once per e2 pair — results
may be higher than expected.

**Workaround:** Use `count_distinct()` on a unique field like `metadata.id`:
```yara
outcome:
  $e1_count = count_distinct($e1.metadata.id)
  $e2_count = count_distinct($e2.metadata.id)
```

### Issue 3: Parentheses at Start of Expression

This triggers a parse error:
```yara
// ❌ Parenthesis at start of expression
(not $e.principal.hostname = "server")

// ✓ Rewrite without leading parenthesis
not $e.principal.hostname = "server"
// or
$e.principal.hostname != "server"
```

### Issue 4: Array Index in Outcome Requires Aggregation

```yara
// ❌ Does not work — array indexing needs aggregation on repeated fields
outcome:
  $dept = $e.principal.user.department[0]

// ✓ Use arrays.index_to_str with aggregation
outcome:
  $dept = arrays.index_to_str(array($e.principal.user.department), 0)
```

### Issue 5: OR in Condition With Multiple Event Variables

`or` in `condition:` is only valid when the query has a **single event variable**:
```yara
// ❌ Invalid — two event variables with OR
condition:
  $e1 or $e2

// ✓ Valid — single event variable
condition:
  $e or #e < 5

// ✓ Valid — use AND for multiple event variables
condition:
  $e1 and $e2
```

### Issue 6: GeoIP Enrichment Eventual Consistency

GeoIP enrichment is eventually consistent — very recent events may not yet have
geolocation data. Rules filtering on `ip_geo_artifact.*` fields may miss events
until enrichment completes (typically minutes). For real-time detection on geo
fields, add a null-value filter and expect some detection delay.

### Issue 7: Future-Dated Events in Multi-Event Rules

Multi-event rules don't create detections for events with future timestamps.
If your data sources sometimes produce events with future-dated timestamps,
those events will be skipped in multi-event rule evaluation.
