# Source: https://docs.cloud.google.com/chronicle/docs/investigation/yara-l-2-0-conditions

# Use the condition syntax in search and dashboards
Supported in:    Google secops   SIEM
This document provides a technical overview of the `condition` section within the YARA-L 2.0 syntax. This section defines the specific criteria used to filter and include data in search results.
These conditions are evaluated against event and placeholder variables previously established in the events section. To refine logic or enforce multiple requirements, you can combine these conditions using the `and` keyword.
## Limitations
Conditions in search have the following limitations:
Required: The `match` section is mandatory. Alternatively, you can define ungrouped filters directly within the `events` section.
Required: Event and placeholder variables must be aggregated within the `condition` section.
Only integer and float comparison expressions are supported. These expressions must have a variable on the left and an integer or float on the right (for example, `#c > 1`, `$port = 80`). Supported operators are `<`, `>`, and `=`.
The order of variables and clauses within the `condition` section doesn't affect the results.
To use outcome variables in the `condition` section, define and aggregate them. You can filter unaggregated outcome variables in the `events` section.
Direct mathematical operations with variables are not supported (for example, `#e1 + 5 > 6`, `$o1.sum($pl) > 0`).
There are no additional restrictions if the `OR` conditions apply to the same base events. The following restrictions apply when `OR` is used across different events:
Nonexistence comparisons are not supported with `OR`. For example, `math.log($outcome1_sent_bytes) > 5 OR (#placeholder2) < 10` is not supported.
Non-UDM variables are not supported in `OR` clauses that span different events. However, `OR` is supported within a single event context or when grouped with `AND`. For example, `$entity and ($udm_event_1 or $placeholder_derived_from_udm_event_1)`. Here's another example, `$entity and ($udm_event_1 or $outcome_udm_event_1_bytes > 1000)`.
## Count character (`#`)
The `#` character, when preceding an event or placeholder variable name (for example, `#c`), represents the number of distinct occurrences of that event or the number of distinct values satisfying all the conditions in the `events` section associated with that variable. For example, `#c > 1` implies that the event or placeholder `c` must occur more than once.
Sample query:
```
$e1.principal.hostname = $hostname
$e1.target.hostname = "fedex.com"
$e1.target.port = 3042 // tcp/udp

$e2.principal.hostname = $hostname
$e2.target.hostname = "homedepot.com"
$e2.target.port = 3042 // tcp/udp

match:
$hostname over 1h

condition:
#e1 > 0 or #e2 > 1

```
## Value character (`$`)
The `$` character's function depends on the context.
Outcome variable: When placed before an outcome variable name (for example, `$risk_score`), it represents the variable's value.
Event or placeholder variable: When placed before an event or placeholder variable name (for example, `$event`), it's equivalent to `#event > 0` and implies that at least one occurrence of that event must exist.
## Event and placeholder conditions
You can combine multiple condition predicates for events and placeholder variables using the `and` keyword.
`or` usage example (single event):
```
condition:
  $ph2 and $ph3

```
Important: When writing logic in the `events` or `condition` sections, use `!` for negation. Use the `not` keyword only in the `outcome` section.
## Bounded and unbounded conditions
Event variable conditions can be bounded or unbounded.
Bounded conditions require the associated event variable to exist. This means that at least one occurrence of the event must appear in any detection.
Examples:  `$var` (equivalent to `#var > 0`) `#var > n` (where `n >= 0`) `#var >= m` (where `m > 0`)
Sample query:
```
$e1.principal.hostname = $hostname
$e1.target.hostname = "fedex.com"

match:
$hostname over 1h

condition:
#e1 > 0

```
Unbounded conditions allow the associated event variable to not exist. This means that it is possible that no occurrence of the event appears in a detection. Any reference to fields on the event variable yields a zero value. Use these for non-existence searches.
Examples:  `!$var` (equivalent to `#var = 0`) `#var >= 0` `#var < n` (where `n > 0`) `#var <= m` (where `m >= 0`)
Sample query:
```
$e1.principal.hostname = $hostname
$e1.target.hostname = "fedex.com"
$e1.target.port = 3042 // tcp/udp

match:
$hostname over 1h

outcome:
$bytes_sent = sum($e1.network.sent_bytes)

condition:
$bytes_sent >= 0

```
Note: For non-existence search queries (using unbounded conditions), the detection engine adds a 1-hour delay to the expected latency.
Search queries with unbounded conditions must meet the following criteria:
At least one UDM event must have a bounded condition; that is, at least one UDM event must exist.
Placeholders with unbounded conditions must associate with at least one bounded UDM event.
Entities with unbounded conditions must associate with at least one bounded UDM event.
## Outcome conditions
You can define outcome conditions using outcome variables, and combine them with logical operators (`and`, `or`, `not`). The comparison syntax depends on the outcome variable's data type.  integer and float: Use `=`, `>`, `>=`, `<`, `<=`, `!=` (for example, `$risk_score > 10`, `$risk_score <= 5.5`). string: Use `=` or `!=` (for example, `$severity = "HIGH"`). list of integers or arrays: Use `arrays.contains()` (for example, `arrays.contains($event_ids, "id_1234")`).
Sample query:
```
$e1.principal.hostname = $hostname
$e1.target.hostname = "fedex.com"
$e1.target.port = 3042 // tcp/udp
match:
$hostname over 1h

outcome:
$bytes_sent = sum($e1.network.sent_bytes)

condition:
$e1

```
## N of X conditions in UDM search
UDM search conditions support "N of X" syntax, which gives a flexible evaluation of multiple criteria. This syntax lets you specify that a condition is met if `N` (a specific number) of `X` (a list of boolean expressions) evaluate to true.
Example: Consider a scenario where you want to identify processes exhibiting several suspicious behaviors, but not necessarily all of them, from a predefined list of tags provided by VirusTotal (VT) enrichment. The "N of X" syntax addresses this by letting you specify a minimum number of conditions that must be met.
The following UDM search query looks for processes where at least three of the conditions are true:
```

$e.metadata.event_type = "PROCESS_LAUNCH"
$e.target.process.file.full_path = $process

match:
    $process

outcome:
    $first_seen = earliest($e.metadata.event_timestamp)
    $last_seen = latest($e.metadata.event_timestamp)
    $total_events = count($e.metadata.id)
    // Collect all unique tags associated with this process from all its launch events
    $tags = array_distinct($e.target.process.file.tags)

condition:
    // Trigger if at least 3 of the following conditions (tag checks) are true
    3 of [
      arrays.contains($tags, "malware"),
      arrays.contains($tags, "detect-debug-environment"),
      arrays.contains($tags, "checks-disk-space"),
      arrays.contains($tags, "checks-cpu-name"),
      arrays.contains($tags, "invalid-signature"),
      arrays.contains($tags, "self-delete")
    ]

order:
    $total_events desc

```
### ANY of and ALL of operators
`ANY of [expressions]` evaluates to `true` if at least one of the listed boolean expressions is `true`. `ALL of [expressions]` requires every listed expression to be `true`. Combine these operators with other conditions using keywords like `AND`. Tip: `ALL of [expressions]` is less efficient than linking each condition with `AND`. Whenever possible, use `AND` for better query performance.
Example:
```

$e.metadata.event_type = "PROCESS_LAUNCH"
$e.target.process.file.full_path = $process

match:
 $process

outcome:
  $first_seen = timestamp.get_timestamp(min($e.metadata.event_timestamp.seconds))
  $last_seen = timestamp.get_timestamp(max($e.metadata.event_timestamp.seconds))
  $total = count($e.metadata.id)
  $tags = array_distinct($e.target.process.file.tags)
  $vt_first_seen_time = max(if((timestamp.current_seconds() - $e.target.process.file.first_seen_time.seconds) < 86400, 1 , 0))
  $vt_last_analysis_time = max(if((timestamp.current_seconds() - $e.target.process.file.last_analysis_time.seconds) < 86400, 1 , 0))
  $vt_last_modification_time = max(if((timestamp.current_seconds() - $e.target.process.file.last_modification_time.seconds) < 86400, 1 , 0))
  $vt_last_seen_time = max(if((timestamp.current_seconds() - $e.target.process.file.last_seen_time.seconds) < 86400, 1 , 0))

condition:
  3 of [
    arrays.contains($tags, "malware"),
    arrays.contains($tags, "detect-debug-environment"),
    arrays.contains($tags, "checks-disk-space"),
    arrays.contains($tags, "checks-cpu-name"),
    arrays.contains($tags, "invalid-signature"),
    arrays.contains($tags, "self-delete")
  ]
  and ANY of [
    $vt_first_seen_time = 1,
    $vt_last_analysis_time = 1,
    $vt_last_modification_time = 1,
    $vt_last_seen_time = 1
  ]

order:
  $total desc

unselect:
    $vt_first_seen_time,
    $vt_last_analysis_time,
    $vt_last_modification_time,
    $vt_last_seen_time

```