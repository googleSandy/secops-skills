# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/nested-if

# Use nested if statements for more complex logic
Supported in:    Google secops   SIEM
You can use `if` statements in both the `outcome` and `events` sections. You can also use `if` statements within the `then` `else` clauses of another `if` statement. This capability lets you introduce more complicated logic to your query.
This syntax is supported in Rules, Search, and Dashboards.
## Syntax
```
if(BOOL_CLAUSE, THEN_CLAUSE, ELSE_CLAUSE)

```
## Nested `if` examples
### Search example: outcome section
This example assigns an outcome score based on `principal.hostname`.
```
$nested_if.principal.hostname != ""
outcome:
    $score = max(
        if($nested_if.principal.hostname = /win-adfs/,
           5,
          if($nested_if.principal.hostname = /server/,
             3,
            if($nested_if.principal.hostname = /win-atomic/,
               1,
               0))))

```
### Search example: events section
This example assigns the placeholder IP to `target.ip` or `principal.ip` so long as they're non-empty. If the IP values are missing, it assigns `no_valid_ip`.
```
events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $ip = if($e.target.ip != "",
            $e.target.ip,
            if($e.principal.ip != "",
              $e.principal.ip,
              "no_valid_ip"))
match:
   $ip

```
### Rule example: nested `if` in `outcome` section
```
rule nested_if_outcome_example {
meta:

events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.principal.ip = $ip
match:
   $ip over 5m
outcome:
    $score = max(
        if($e.principal.hostname = /win-adfs/,
           5,
          if($e.principal.hostname = /server/,
             3,
            if($e.principal.hostname = /win-atomic/,
               1,
               0))))
  condition:
    $e
}

```
### Rule example: nested `if` in `events` section
```
rule nested_if_events_example {

meta:

events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $ip = if($e.target.ip != "",
            $e.target.ip,
            if($e.principal.ip != "",
              $e.principal.ip,
              "no_valid_ip"))
match:
   $ip over 5m

  condition:
    $e
}

```
## Known limitation
The `if()` statement is a function in YARA-L 2.0 and subject to the function depth limit of 20.