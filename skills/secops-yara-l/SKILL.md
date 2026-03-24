---
name: secops-yara-l
description: |
  Use when writing YARA-L 2.0 detection rules or complex search queries for Google
  SecOps — single-event rules, multi-event correlation, sliding window detections,
  composite rules, outcome aggregations, conditional logic, multi-stage queries, or
  any YARA-L syntax questions. Triggers: "write a detection rule", "create a rule",
  "YARA-L rule for", "detect when", "alert when", "correlate events", "multi-stage
  query", "composite detection", "outcome section", "match over".
compatibility: Requires access to a Google Security Operations (SecOps) SIEM instance with Detection Engine enabled.
---

# SecOps YARA-L 2.0

## Section Order

| # | Section | Rules | Search/Dashboards | Purpose |
|---|---|---|---|---|
| 1 | `meta` | Required | Optional | Author, description, severity, tags |
| 2 | `events` | Required | Required | Declare event variables and filter conditions |
| 3 | `match` | Required* | Optional | Group-by keys + time window |
| 4 | `outcome` | Optional | Optional | Aggregate computations, risk scores |
| 5 | `condition` | Required | Optional | Trigger logic (`#var`, `$var`) |
| 6 | `options` | Optional | Optional | Rule behavior flags |
| 7 | `dedup` | — | Optional | Deduplicate results |
| 8 | `order` | — | Optional | Sort results |
| 9 | `limit` | — | Optional | Cap result count |
| 10 | `select` / `unselect` | — | Optional | Control output columns |

*`match` optional if rule matches a single event with no time correlation.

---

## Complete Rule Example

```yara
rule MultipleFailedLogins {
  meta:
    author        = "Security Team"
    description   = "Detects 5+ failed logins for the same user within 10 minutes"
    severity      = "HIGH"
    type          = "alert_rule"

  events:
    $e.metadata.event_type     = "USER_LOGIN"
    $e.security_result.action  = "FAIL"
    $user = $e.target.user.userid   // placeholder variable = join key

  match:
    $user over 10m              // group by $user within 10-minute hop window

  outcome:
    $count     = count($e.metadata.id)
    $usernames = array_distinct($e.target.user.userid)

  condition:
    #e > 5                      // fire when more than 5 events match

  options:
    allow_zero_values = true
}
```

---

## Variable Types

| Type | Syntax | Scope | Purpose |
|---|---|---|---|
| **Event variable** | `$e`, `$login`, `$file` | `events:` | References a specific event; prefix for field access |
| **Placeholder variable** | `$user`, `$ip` | `events:` + `match:` | Join key — shared value across events; group-by key |
| **Outcome variable** | `$count`, `$score` | `outcome:` | Computed aggregate, referenced in `condition:` with `$` |

**Event variable field access:** `$e.metadata.event_type`, `$login.principal.ip`

**Placeholder assignment (both forms equivalent):**
```yara
$user = $e.target.user.userid
$e.principal.hostname = $host
```

**Transitive join** (links $e1 and $e2 through shared $ip):
```yara
$ip = $e1.principal.ip
$ip = $e2.target.ip   // equivalent to $e1.principal.ip = $e2.target.ip
```

---

## Window Types

| Type | Syntax | Behavior | Use case |
|---|---|---|---|
| **Hop** (default) | `$key over 5m` | Overlapping windows | General multi-event correlation |
| **Tumbling** | `$key by 30m tumbling` | Fixed, non-overlapping | Count activity per time block |
| **Sliding** | `$key over 10m after $pivot` | Anchored to a pivot event | Strict sequencing (A then B) |

Min window: `1m` · Max window: `48h`

---

## Condition Logic

| Expression | Meaning |
|---|---|
| `$e` | `#e > 0` — event must exist at least once |
| `#e > 5` | More than 5 distinct occurrences of `$e` |
| `#e >= 1` | At least 1 occurrence (bounded — event must exist) |
| `$count > 100` | Outcome variable value comparison |
| `$e and $e2` | Both event variables must be present |
| `$e and not $e2` | $e exists, $e2 does not (non-existence / unbounded) |

**`#` = count of distinct events/values**
**`$` before event var = existence check (`#var > 0`)**
**`$` before outcome var = the computed value**

`or` is only valid in condition when the query has a **single event variable**.

→ Full condition reference: `references/syntax.md`

---

## Key Patterns

**Single event (no match section):**
```yara
rule SuspiciousLogin {
  meta:
    severity = "MEDIUM"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.principal.ip in %suspicious_ips
  condition:
    $e
}
```

**Multi-event correlation:**
```yara
rule LoginThenDeletion {
  meta:
    severity = "HIGH"
  events:
    $user = $login.principal.user.userid
    $login.metadata.event_type = "USER_LOGIN"
    $login.security_result.action = "ALLOW"

    $user = $del.principal.user.userid
    $del.metadata.event_type = "FILE_DELETION"
  match:
    $user over 30m
  condition:
    $login and $del
}
```

**Sliding window (strict sequence):**
```yara
match:
  $user over 1h after $login   // $login is the pivot event
```

**Threshold with outcome:**
```yara
outcome:
  $distinct_ips = count_distinct($e.principal.ip)
condition:
  $distinct_ips > 10
```

---

## Gotchas

Environment-specific facts that defy reasonable assumptions:

- **`/i` flag does not exist** — `/pattern/i` is invalid. Use `/pattern/ nocase` (space before nocase):
  ```
  ❌  $e.target.process.file.names /trufflehog/i
  ✓   $e.target.process.file.names = /trufflehog/ nocase
  ```
- **Missing `=` before regex literals** — the `=` operator is required between field and regex:
  ```
  ❌  $e.target.process.file.names /wscript\.exe/
  ✓   $e.target.process.file.names = /wscript\.exe/ nocase
  ```
- **`/` inside regex must be escaped as `\/`** — the regex delimiter is `/`, so a literal forward slash inside requires `\/`. Windows paths use `\` (escaped as `\\` in regex), not `/`:
  ```
  ❌  $e.target.file.full_path = /^[d-zD-Z]:\//   // forward slash closes the regex early
  ✓   $e.target.file.full_path = /^[d-zD-Z]:\\/   // backslash — correct Windows path separator
  ```
- **When using OR branches with different `metadata.event_type` values, use a separate event variable** — filtering on two different event types inside `(A or B)` branches for the same event variable causes compile errors. Use a new variable for the branched behavior:
  ```
  ❌  // Same $file variable with different event_type in OR branches
      ($file.metadata.event_type = "FILE_CREATION" or $file.metadata.event_type = "FILE_COPY")

  ✓   // Use separate $action variable — let the branches filter event_type
      $action.principal.process.pid = $process_pid
      ($action.metadata.event_type = "FILE_CREATION" or $action.metadata.event_type = "FILE_COPY")
  ```
- **Use `$process_pid` to link parent and child events precisely** — joining on hostname alone can create false correlations. Capture the PID from Event 1 and match it as the principal PID in Event 2:
  ```
  $process_pid = $exec.target.process.pid       // capture in Event 1
  $action.principal.process.pid = $process_pid  // match in Event 2
  ```
- **Enumerated fields reject regex** — `metadata.event_type = /USER_.*/` is a compile error; list values with `or`:
  ```
  ❌  $e.metadata.event_type = /USER_LOGIN|USER_LOGOUT/
  ✓   ($e.metadata.event_type = "USER_LOGIN" or $e.metadata.event_type = "USER_LOGOUT")
  ```
- **`nocase` is invalid on string literals** — `= "VALUE" nocase` fails; use `= /VALUE/ nocase`
- **Single-event rules should NOT have a `match:` section** — omit it entirely; adding `match:` to a single-event rule delays detection unnecessarily
- **New rules are NOT live by default** — saving does not enable a rule. Toggle the Live Rule switch manually.
- **Reference lists are deprecated (June 2026)** — use data tables (`%table.column`) for new rules
- **Non-existence conditions add ~1h detection delay** — `not $e2` in `condition:` waits for late-arriving data
- **`suppression_window` is NOT applied during Run Test** — test results won't reflect suppression behavior
- **Multi-event rules need `match:` window ≥ retrohunt time range** — retrohunts fail if time range < match window
- **`count()` requires a field argument** — `count()` alone is a compile error; use `count(field)`
- **Rules with alerting disabled generate no alerts in retrohunt** — enable alerting before retrohunting

## Reference Files

- Read `references/cheat-sheet.md` for a quick reminder of any YARA-L syntax at a glance
- Read `references/syntax.md` for full section syntax (meta, events, match, outcome, condition, options, setup, export) or rules-vs-search differences
- Read `references/expressions.md` for operator details, regex flags, reference list syntax, `any`/`all`, or map access patterns
- Read `references/functions.md` when you need a specific function signature or list of available aggregate/built-in functions
- Read `examples/` when building a new rule and want a complete working example to adapt
- Read `references/multi-stage.md` when building multi-stage search queries, Z-score/MAD anomaly detection, or metrics behavioral analytics
- Read `references/best-practices.md` when a rule isn't firing as expected, or to avoid zero-value joins, repeated field pitfalls, or GeoIP issues
