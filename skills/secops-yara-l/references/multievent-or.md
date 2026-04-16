# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/multievent-or

# Use or in the condition section
Supported in:    Google secops   SIEM
This document explains how to use the `or` operator to write flexible and concise detection logic within the `condition` section of your query.
Using `or` between event or placeholder variables lets you combine multiple conditions, reducing the overall complexity of your query syntax:  Checks for the presence of either of the specified variables. For example, `$e1 or $e2` requires at least one instance of `$e1` or one instance of `$e2`.
## `or` syntax in condition section
Use the `or` keyword directly between variables. The following example is equivalent of `COUNT($e1)>0 or COUNT($e2)>0`:
```
condition:
  $e1 or $e2  // True if $e1 exists or $e2 exists

```
## Example rule: risky IP or bad hash execution
The following example rule detects a threat if a process launch from a risky IP address is detected or a known bad hash is executed:
```
rule MultiEventOr {
  meta:
    author = "google-secops"
  events:
    $e1.principal.ip = "1.1.1.1"
    $e1.metadata.event_type = "PROCESS_LAUNCH"
    $e2.target.file.sha256 = "badhash..."
    $user = $e1.principal.user.userid
    $user = $e2.principal.user.userid
  match:
    $user over 5m
  condition:
    $e1 or $e2
}

```
## Example search: risky IP or bad hash execution
The following example shows how you could reformat the example rule as a search query. Note: You must specify `event` variables when using a multi-event `or` in the `condition` section.
```
$e1.principal.ip = "1.1.1.1"
$e1.metadata.event_type = "PROCESS_LAUNCH"
$e2.target.file.sha256 = "badhash..."
$user = $e1.principal.user.userid
$user = $e2.principal.user.userid

match:
  $user over 5m

condition:
  $e1 or $e2

```
## Known limitations
Resource consumption: When you use `or` between event variables, it consumes more resources than using `and` and can result in longer query execution times.
Event variable limit: For Search and Dashboards, you can use maximum of 3 events in multi-event `or` syntax. For Rules, you can use maximum of 2 events in multi-event `or` syntax.
Required event existence: Expressions using `or` can't be unbounded. The existence of the event must be a requirement for the clause to be true (for example, `$e1` or `#e1 > 0`).
Variable type mixing: You can't combine non-UDM variables with UDM event variables within the same `or` list.
Window restriction: You can't use tumbling windows with `or` syntax.