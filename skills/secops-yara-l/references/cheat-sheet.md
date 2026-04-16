# YARA-L 2.0 Quick Reference Cheat Sheet

Source: https://github.com/Matchistador/Yara-L/blob/main/YARA-L%20cheat%20sheet.pdf

---

## Search Syntax at a Glance

```yara
// UDM search (events: section implied)
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"

// Grouped fields shorthand (UDM search only)
user = "root"
domain = "www.example.com" nocase

// Raw log search
raw = "mimikatz"
raw = /sekurlsa/ nocase
raw = /./ AND parsed = false    // logs that failed to parse

// Launch search: Cmd+Enter / Alt+Enter shortcut
```

---

## Statistics (Aggregation)

```yara
match:
  domain, user                    // group by multiple fields

// Window types:
match: $user over 1d              // Hop (overlapping, default for rules)
match: $user by day               // Tumbling (fixed, non-overlapping) — creates time_bucket column
match: $user by 1h tumbling       // Tumbling by hour
match: $user over 10m after $login  // Sliding (anchored to pivot event)
```

---

## Outcome Examples

```yara
outcome:
  $data_sent  = sum(network.sent_bytes)
  $score = max(
    if(principal.hostname = /win-adfs/, 5,
      if(principal.hostname = /server/, 3, 0)))
```

**Aggregate functions:** `count` · `count_distinct` · `sum` · `min` · `max` · `stddev` · `avg` · `array` · `array_distinct`

---

## Conditions

```yara
condition: $e               // event must exist (#e > 0)
condition: #e > 5           // more than 5 occurrences
condition: !$e              // event must NOT exist
condition: $e and $e2       // both events must exist
condition: $e and not $e2   // e exists, e2 does not

// ANY of list
condition: ANY of [$vt_first_seen_time = 1, $vt_last_analysis_time = 1]
```

---

## Regex

```yara
re.regex(network.email.from, `.*goggle\.com`)   // function form
network.email.from = /.*goggle\.com/            // inline form (equivalent)
// SecOps uses RE2 library
```

---

## Variables

```yara
$destination = target.ip                    // assign UDM field to variable
// Can also be reversed: target.ip = $destination
// Variables valid in: events: and outcome: sections
```

---

## Modifiers (Search / Dashboards only)

```yara
limit:    42
order:    $count desc
select:   principal.ip
unselect: namespace, $destination
dedup:    target.hostname
```

---

## Entity Graph Search

```yara
graph.metadata.entity_type = "FILE"
graph.metadata.entity_type = "ASSET" AND net.ip_in_range_cidr(graph.entity.ip, "192.168.0.0/16")
// Entity Graph stores contextual data: assets, users, IOCs, prevalence
```

---

## Data Tables

```yara
// Row-based join (match on any column)
target.hostname = %very_suspicious.hostname

// Column-based comparison
not security_result.rule_name in regex %white_rules.regex
```

---

## Joins (Left/Right) — Entity Graph

```yara
$e.metadata.event_type = "NETWORK_CONNECTION"
$g.graph.metadata.entity_type = "ASSET"
left join $e.principal.asset.hostname = $g.graph.entity.asset.hostname
// Two different event types → use event variables ($e, $g) for each
```

---

## Export to Data Tables (Rules only)

```yara
export:
  %mydatatable.write_row(host: $hostname, port: $port_nb)
```

---

## Multi-Stage Rules

```yara
// Named stage — must be defined before root stage
stage absolute_deviations {
  ...
  outcome:
    $host = principal.hostname
    $deviation = ...
}

// Root stage — references named stage output
$host = $absolute_deviations.host
$deviation = $absolute_deviations.deviation
match:
  $host
condition:
  $deviation > 3
```

---

## Complete Rule Template

```yara
rule RuleName {
  meta:
    author      = "Security Team"
    description = "What this detects"
    severity    = "HIGH"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $user = $e.principal.user.userid

  match:
    $user over 10m

  outcome:
    $count = count($e.metadata.id)

  condition:
    #e > 5

  options:
    allow_zero_values = true
}
```
