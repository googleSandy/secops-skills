# YARA-L 2.0: Section Syntax Reference

## meta

Required in rules. Not used in search/dashboard queries. Must appear first.

**Production standard fields** (from https://github.com/chronicle/detection-rules):
```yara
meta:
  author                    = "Google Cloud Security"
  description               = "What this detects."
  rule_id                   = "mr_<UUID>"
  rule_name                 = "Human Readable Rule Name"
  mitre_attack_tactic       = "Credential Access"
  mitre_attack_technique    = "Brute Force: Password Spraying"
  mitre_attack_url          = "https://attack.mitre.org/techniques/T1110/003/"
  mitre_attack_version      = "v14.1"
  type                      = "Alert"          // Alert, Hunt, or Informational
  data_source               = "Okta"
  platform                  = "SaaS"           // optional
  severity                  = "High"           // Critical, High, Medium, Low
  priority                  = "High"
  reference                 = "https://..."    // optional
  assumption                = "Assumes X is ingested into entity graph"  // optional
```

**Minimal example:**
```yara
meta:
  author      = "Security Team"
  description = "Detects brute force login attempts"
  severity    = "HIGH"
  type        = "alert_rule"
  tags        = "t1110, brute-force"
```

Key-value pairs. Keys are unquoted strings; values are quoted strings. No fixed schema —
add any fields relevant to your team. Common keys: `author`, `description`, `severity`,
`type`, `tags`, `mitre_attack_technique`, `reference`.

---

## events

Declares event variables and filter conditions. Required in both rules and search.

**Single event:**
```yara
events:
  $e.metadata.event_type = "USER_LOGIN"
  $e.security_result.action = "FAIL"
```

**Multi-event (each needs its own variable):**
```yara
events:
  // Event 1
  $login.metadata.event_type = "USER_LOGIN"
  $login.security_result.action = "ALLOW"
  $user = $login.principal.user.userid     // placeholder — becomes join key

  // Event 2 (joined via $user)
  $del.metadata.event_type = "FILE_DELETION"
  $user = $del.principal.user.userid
```

**Variable declaration forms (equivalent):**
```yara
$user = $e.target.user.userid
$e.principal.hostname = $host
```

**Transitive join:**
```yara
$e1.source.ip = $ip
$e2.target.ip = $ip
// equivalent to: $e1.source.ip = $e2.target.ip
```

**`any` and `all` for repeated fields:**
```yara
any $e.target.ip in %suspicious_ips      // true if ANY ip matches
all $e.target.ip in %suspicious_ips      // true if ALL ips match
```

**Note:** Event variables (`$e`, `$login`) are required in rules but optional in search/dashboards.

**Production patterns for events: section:**

```yara
// Filter by vendor + product for SaaS sources (always do this)
$e.metadata.vendor_name = "Okta"
$e.metadata.product_name = "Okta"
$e.metadata.product_event_type = "user.authentication.auth_via_mfa"

// Timestamp ordering — enforce event sequence
$e1.metadata.event_timestamp.seconds <= $e2.metadata.event_timestamp.seconds

// Map field access
$e.target.resource.attribute.labels["ser_binding_deltas_role"] = /roles\/owner/ nocase
$e.security_result.detection_fields["key_id"] = $sa_key_id
$e.about.labels["is_suspicious"] = "true"

// Geolocation: check field is populated and not internal
$e.principal.ip_geo_artifact.location.country_or_region != ""
$e.principal.ip_geo_artifact.network.organization_name != /google/

// Direct field comparison join (different namespaces, same user)
$login.target.user.userid = $download.principal.user.userid
```

---

## match

Groups events by placeholder variables within a time window. Required for multi-event rules.

```yara
match:
  $user, $host over 10m           // hop window (default)
  $user by 30m tumbling           // tumbling window
  $user over 1h after $login      // sliding window, $login is pivot
  $user over 1h before $file_del  // sliding window, fire before event
```

**Window types:**

| Type | Syntax | Behavior |
|---|---|---|
| Hop | `over Xm` | Overlapping, continuous — default |
| Tumbling | `by Xm tumbling` | Fixed, non-overlapping blocks |
| Sliding | `over Xm after $pivot` or `before $pivot` | Anchored to a specific pivot event |

Limits: min `1m`, max `48h`.

**Rules vs Search/Dashboards:**
- Rules: `over <duration>` required
- Search/Dashboards: time window optional; can use `by Xh` for granularity

**Zero values in match:** By default, placeholder variables with zero/empty values are filtered out.
Use `options: allow_zero_values = true` to include them.

---

## outcome

Computes up to 20 aggregate variables. Values are referenced in `condition:` with `$`.

**Standard production outcome block** — include in every rule for triage context:
```yara
outcome:
  $risk_score                       = max(35)   // 35=low, 65=medium, 85=high
  $event_count                      = count_distinct($e.metadata.id)
  $principal_ip                     = array_distinct($e.principal.ip)
  $principal_ip_country             = array_distinct($e.principal.ip_geo_artifact.location.country_or_region)
  $principal_user_userid            = array_distinct($e.principal.user.userid)
  $principal_user_display_name      = array_distinct($e.principal.user.user_display_name)
  $principal_process_file_full_path = array_distinct($e.principal.process.file.full_path)
  $principal_process_command_line   = array_distinct($e.principal.process.command_line)
  $target_resource_name             = array_distinct($e.target.resource.name)
```

**Outcome variable used in condition** (compute in outcome, check in condition):
```yara
outcome:
  $dc_country = count_distinct($e.principal.ip_geo_artifact.location.country_or_region)

condition:
  $e and $dc_country > 2    // fire only when activity spans 3+ countries
```

**Supported data types:** integer, float, string, list of integers, list of floats, list of strings.

**Conditional logic:**
```yara
if(BOOL_CLAUSE, THEN_CLAUSE)
if(BOOL_CLAUSE, THEN_CLAUSE, ELSE_CLAUSE)
```

**Mathematical operations:**
```yara
$total = $sent_bytes + $recv_bytes
$ratio = $failed / $total
```

**risk_score and risk_entity_to_score:**
```yara
outcome:
  $risk_score = 50                          // assigns risk score to the detection
  $risk_entity_to_score = $e.principal.ip   // specifies which entity gets the score
```

**Repeated fields in outcome with match window:** Use aggregate functions — non-scalar values
require aggregation:
```yara
$hostnames = array($e.principal.hostname)   // collect into list
$count     = count($e.metadata.id)          // scalar aggregate
```

---

## condition

Required in rules. Defines when a detection fires.

```yara
condition:
  $e                          // #e > 0 — event must exist (bounded)
  #e > 5                      // more than 5 occurrences
  #login >= 3 and #login < 10 // range
  $e and $e2                  // both events must exist
  $e and not $e2              // e exists, e2 does not (non-existence)
  $count > 1000               // outcome variable threshold
```

**`#var`** = count of distinct events/values satisfying all `events:` conditions for that variable.
**`$var`** before an event var = `#var > 0` (existence). Before an outcome var = the computed value.

**Bounded conditions** (event must exist):
- `$var` → `#var > 0`
- `#var > n` (n ≥ 0)
- `#var >= m` (m > 0)

**Unbounded conditions** (event may not exist — for non-existence queries):
- `!$var` → `#var = 0`
- `#var < n` (n > 0)
- `#var >= 0`

**OR restriction:** `or` in condition only valid when query has a **single event variable**.

**Non-existence note:** Detection engine adds ~1h delay for non-existence queries to allow for late data.

**Outcome conditions:**
```yara
condition:
  $e and $count > 5    // event must exist AND outcome threshold met
```

---

## options

```yara
options:
  allow_zero_values  = true    // include zero-value placeholders in match
  suppression_window = 3600    // suppress duplicate alerts for N seconds
```

**allow_zero_values:** Default `false`. When `false`, placeholders with empty string / zero value
in the `match` section are filtered out (prevents false positive joins on empty fields).
Enable when you legitimately need to match zero-value fields.

**suppression_window:** Suppresses duplicate detections for the same entity within N seconds.
Useful for noisy rules.

---

## dedup (Search/Dashboards only)

Removes duplicate results grouped by key fields or variables.

```yara
dedup:
  target.user.userid, target.ip   // deduplicate by UDM fields
  $host, $user                    // or by placeholder variables
```

---

## select / unselect (Search/Dashboards only)

Control which UDM fields appear as columns in the Events table.

```yara
// Add a column
select: security_result.about.email

// Add multiple columns
select: target.asset.hostname, principal.process.command_line

// Remove a column
unselect: principal.hostname
```

---

## Rules vs Search: Key Differences

| Feature | Rules | Search / Dashboards |
|---|---|---|
| `rule Name { }` wrapper | Required | Not used |
| `meta:` | Required | Not used |
| Event variables (`$e`) | Required | Optional |
| `match:` time window | `over Xm` required for multi-event | Optional; `by Xm` for granularity |
| `condition:` | Required | Optional |
| `options:` | Supported | Supported |
| `dedup:` | Not applicable | Supported |
| `order:` / `limit:` / `select:` | Not applicable | Supported |
| `export:` | Rules only | Not applicable |

---

## setup (Rules only — Entity Graph Filtering)

The `setup:` section appears before `events:` and configures entity graph filtering
using data tables. Used with `graph_exclude` and `graph_override`.

```yara
// Exclude entities matching data table from rule evaluation
setup:
  graph_exclude($graph.graph.entity.user.userid = %allowlisted_users.userid)

// Override entity field value with data table value
setup:
  graph_override($graph.graph.entity.user.department = %dept_mappings.department
                 WHERE $graph.graph.entity.user.userid = %dept_mappings.userid)
```

**graph_exclude:** If the entity graph field matches the data table column, that entity is
excluded from the rule — the rule won't fire for matched entities.

**graph_override:** Replaces entity graph values with data table values before events evaluation.

**Note:** Reference lists are deprecated (June 2026) — use data tables for list-based filtering.

---

## export (Rules only)

Write rule detection results to a data table. Executed each time the rule fires a detection.

```yara
export:
  %mydatatable.write_row(
      host:    $hostname,
      port:    $port_nb,
      src_ip:  $ip
  )
```

Column names in the function call must match columns defined in the data table.
Only available in detection rules — not search or dashboards.
