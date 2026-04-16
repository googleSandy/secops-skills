# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/condition-syntax

# Condition section syntax
Supported in:    Google secops   SIEM
This document describes how you can use the `condition` section of a YARA-L 2.0 query.
The impact of the `condition` section depends on whether you're executing an ad-hoc query or deploying a persistent rule as follows:  For Search and Dashboards: Acts as a post-filter, only returning and rendering records that satisfy the specified expressions. Detection Rules (required): Serves as the trigger logic. An alert only triggers if the conditions resolve to `true` for a given `match` window.
Use the `condition` section to define expressions that filter events and placeholder variables. When used in a search or dashboard query, it only shows output that meets the conditions. When used in a detection rule, the conditions must be met to trigger an alert.
In the `condition` section, you can use boolean operators, comparison operators, and results of `outcome` variables to determine if the query should trigger.
## Define the `condition` section
Define the condition expressions for events and placeholder variables from the `condition` section. You can specify `match` conditions for variables from the `events` section and, optionally, use the `and` keyword to include logic based on the `outcome` section. For details, see the Outcome section syntax.
You can join the expressions using the `and` or `or` keywords:
Use `and` between any conditions.
Use `or` only when the query contains a single event variable.
Use the `#` character in the `condition` section before any event or placeholder variable name to represent the number of distinct events or values that satisfy all of the conditions in the `events` section. For example:
`#c > 1` means the variable `c` must occur more than 1 time.
Use the `$` character in the `condition` section before any outcome variable name to represent the value of that outcome. If used before any event or placeholder variable name (for example, `$event`), it represents `#event > 0`.
This rule example returns a detection when there are greater than five (as defined in the `condition` section) failed logins for each user within a 10-minute window (as defined in the `match` section):
```
rule failed_logins
{
  meta:
   author = "Security Team"
   description = "Detects multiple failed user logins within 10-minute windows."
   severity = "HIGH"

  events:
   $e.metadata.event_type = "USER_LOGIN"
   $e.security_result.action = "FAIL"
   $user = $e.target.user.userid

  match:
   $user over 10m

  outcome:
   $failed_login_count = count($e.metadata.id)
   $first_fail_time = min($e.metadata.event_timestamp.seconds)

  condition:
    #e >= 5
}

```
## Bounded and unbounded conditions
You can use bounded or unbounded conditions in a query:
Bounded conditions force the associated event variable to exist, which means at least one occurrence of the event must appear in the detection. The following are bounded conditions:
`$var // equivalent to #var > 0`
`#var > n // where n >= 0`
`#var >= m // where m > 0`
Unbounded conditions can be used to detect the absence of an event over a period of time; for example, a threat event without a mitigation event within a 10 minute window. Unbounded conditions allow the associated event variable to not exist (non-existence queries), which means it is possible that no occurrence of the event appears in a detection and any reference to fields on the event variable yields a zero value.
The following are unbounded conditions:
`!$var // equivalent to #var = 0`
`#var >= 0`
`#var < n // where n > 0`
`#var <= m // where m >= 0`  Note: For non-existence queries, the detection engine adds a 1 hour delay to the expected latency (based on the query's run frequency) to allow for late-arriving data.
### Requirements for non-existence queries
For a non-existence query to compile, it must satisfy the following requirements:  At least one UDM event must have a bounded condition (that is, at least one UDM event must exist). If a placeholder has an unbounded condition, it must be associated with at least one bounded UDM event. If an entity has an unbounded condition, it must be associated with at least one bounded UDM event.  Note: Avoid using the `not` keyword in event and placeholder conditions.
### Example: non-existence query
Consider the following query with the condition section omitted:
```
rule NonexistenceExample {
  meta:
      author = "Google Security"
      description = "Example: non-existence query."
  events:
      $u1.metadata.event_type = "NETWORK_CONNECTION" // $u1 is a UDM event.
      $u2.metadata.event_type = "NETWORK_CONNECTION" // $u2 is a UDM event.
      $e1.graph.metadata.entity_type = "FILE"        // $e1 is an entity.
      $e2.graph.metadata.entity_type = "FILE"        // $e2 is an entity.

      $user = $u1.principal.user.userid // Match variable is required for multi-event query.

      // Placeholder Associations:
      //   u1        u2
      //   |  \    /
      // port   ip
      //   |       \
      //   e1        e2
      $u1.target.port = $port
      $e1.graph.entity.port = $port
      $u1.principal.ip = $ip
      $u2.target.ip = $ip
      $e2.graph.entity.ip = $ip

      // UDM-Entity Associations:
      // u1 - u2
      // |  \  |
      // e1   e2
      $u1.metadata.event_type = $u2.metadata.event_type
      $e1.graph.entity.hostname = $u1.principal.hostname
      $e2.graph.entity.hostname = $u1.target.hostname
      $e2.graph.entity.hostname = $u2.principal.hostname

  match:
    $user over 5m

  condition:
      //Add valid condition
}
```
#### Valid condition section
The following are valid examples for the condition section:  `$u1 and !$u2 and $e1 and $e2`  All UDM events and entities are present in the condition section. At least one UDM event is bounded.  `$u1 and !$u2 and $e1 and !$e2`  `$e2`is unbounded and allowed because it is associated with `$u1`, which is bounded. If `$e2` was not associated with `$u1`, this would be invalid.  `#port > 50 and #ip = 0`  No UDM events and entities are present in the condition section; however, the placeholders that are present cover all the UDM events and entities. `$ip` is assigned to both `$u1` and `$u2` and `#ip = 0` is an unbounded condition. However, bounded conditions are stronger than unbounded conditions. Since `$port` is assigned to `$u1` and `#port > 50` is a bounded condition, `$u1` is still bounded.
#### Invalid condition section
The following are invalid examples for the condition section:  `$u1 and $e1`  Every UDM event and entity appearing in the `events` section must appear in the `condition` section (or have a placeholder assigned to it that appears in the `condition` section).  `$u1, $u2, $e1, $u2, #port > 50`  Commas are not allowed as condition separators.  `!$u1 and !$u2 and $e1 and $e2`  Violates the first requirement that at least one UDM event is bounded.  `($u1 or #port < 50) and $u2 and $e1 and $e2`  `or` keyword is not supported with unbounded conditions.  `($u1 or $u2) and $e1 and $e2`  `or` keyword is not supported between different event variables.  `not $u1 and $u2 and $e1 and $e2`  `not` keyword is not allowed for event and placeholder conditions.  `#port < 50 and #ip = 0`  Although the placeholders reference all UDM events and entities, every associated condition is unbounded. This means none of the UDM events are bounded, causing the rule to fail to compile.
## Outcome conditions
You can include conditions for outcome variables in the `condition` section, joined with the `and` or `or` keyword, or preceded by the `not` keyword.
Outcome conditionals are specified differently depending on the type of outcome variable:
integer: compare against an integer literal with operators `=, >, >=, <, <=, !=` For example: `$risk_score > 10`
float: compare against a float literal with operators `=, >, >=, <, <=, !=` For example: `$risk_score <= 5.5`
string: compare against a string literal with either `=` or `!=` For example: `$severity = "HIGH"`
list of integers or arrays: specify condition using the `arrays.contains` function For example: `arrays.contains($event_ids, "id_1234")`  Note: If you use the `or` keyword inside the event or placeholder conditionals subsection, you must surround that entire subsection with parentheses. For example, the following is valid: `($e1 or $e2) and $outcome > 0`.
If you specify an outcome condition in a query that has a `match` section, the query is classified as a multi-event query for query quota. See the Match syntax for more information about single and multiple event classifications.
## Restrictions
Avoid using a `match` variable in the `condition` section. It's a semantic error because events are grouped by the `match` variable value.
Avoid specifying only unbounded conditions on all `event` variables that a `match` variable is assigned to. It's a semantic error. For a `match` variable value to be returned, at least one event must exist that contains the value.
In case of using a sliding window, the pivot event variable must be involved in at least one bounded condition.