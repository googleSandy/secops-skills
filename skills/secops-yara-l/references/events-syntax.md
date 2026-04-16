# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/events-syntax

# Events section syntax
Supported in:    Google secops   SIEM
The `events` section must immediately follow the `meta` section in a rule. It defines which events the query should examine and what specific attributes those events must possess to be considered relevant for a potential detection.
The `events` section is mandatory for rules, but optional for Search and Dashboards.
Use the `events` section to list the predicates specifying the following:  Variable declarations Event variable filters Event variable joins
## Define events section
Rules and queries that are focused on only one event type can include a single event variable, such as:
```
events:
  $e.metadata.event_type = "USER_LOGIN" // 'e' is the common convention for a single event

```
Rules and queries that require correlation between two or more distinct types of events (such as a user login followed by a file modification), require a variable for each type of event:
```
events:
  $login.metadata.event_type = "USER_LOGIN" // Event 1: User Login
  $file_op.metadata.event_type = "FILE_MODIFICATION" // Event 2: File Modification

```
Once an event variable is declared, you use it as a prefix to access specific fields from that event type. For example, the following `event` section filters failed login events from Okta:
```
events:
   $e.metadata.vendor_name = "Okta"
   $e.metadata.event_type = "USER_LOGIN"
   $e.security_result.action = "FAIL"

```
## Variable declarations
For variable declarations, use the following syntax:  `<EVENT_FIELD> = <VAR>` `<VAR> = <EVENT_FIELD>`
Both are equivalent, as shown in the following examples:  `$e.source.hostname = $hostname` `$userid = $e.principal.user.userid`
This declaration indicates that this variable represents the specified field for the event variable. When the event field is a repeated field, the `match` variable can represent any value in the array. You can also assign multiple event fields to a single match or placeholder variable. This is called a transitive join condition.
For example, the following:  `$e1.source.ip = $ip` `$e2.target.ip = $ip`
Are equivalent to:  `$e1.source.ip = $ip` `$e1.source.ip = $e2.target.ip`
When a variable is used, the variable must be declared through variable declaration. If a variable is used without any declaration, it triggers a compilation error. Note: Event variables are required in Rules. However, they are not needed in Search and Dashboards.
For more information about variables, see Expressions, operators, and other constructs.
## Event variable filters
A boolean expression that acts on a single event variable is considered a filter.
## Event variable joins
All event variables used in a rule must be joined with every other event variable in either of the following ways:
Directly through an equality comparison between event fields of the two joined event variables, for example: `$e1.field = $e2.field`. The expression mustn't include arithmetic operations (such as, $\text{+, -, *, /}$).
Indirectly through a transitive join involving only an event field (see variable declaration for a definition of "transitive join"). The expression mustn't include arithmetic.
For example, assuming `$e1`, `$e2`, and `$e3` are used in the rule, the following `events` sections are valid:
```
events:
  $e1.principal.hostname = $e2.src.hostname // $e1 joins with $e2
  $e2.principal.ip = $e3.src.ip // $e2 joins with $e3

```

```
events:
  // $e1 joins with $e2 using function to event comparison
  re.capture($e1.src.hostname, ".*") = $e2.target.hostname

```

```
events:
  // $e1 joins with $e2 using an `or` expression
  $e1.principal.hostname = $e2.src.hostname
  or $e1.principal.hostname = $e2.target.hostname
  or $e1.principal.hostname = $e2.principal.hostname

```

```
events:
  // all of $e1, $e2 and $e3 are transitively joined using the placeholder variable $ip
  $e1.src.ip = $ip
  $e2.target.ip = $ip
  $e3.about.ip = $ip

```

```
events:
  // $e1 and $e2 are transitively joined using function to event comparison
  re.capture($e2.principal.application, ".*") = $app
  $e1.principal.hostname = $app

```
Note: If your sole join condition is an `or` chain, a function to event comparison, or a combination of both, then the rule may perform poorly.
However, the following exampls show invalid `events` sections.
```
events:
  // Event to arithmetic comparison is an invalid join condition for $e1 and $e2.
  $e1.principal.port = $e2.src.port + 1

```

```
events:
  $e1.src.ip = $ip
  $e2.target.ip = $ip
  $e3.about.ip = "192.1.2.0" //$e3 is not joined with $e1 or $e2.

```

```
events:
  $e1.src.port = $port

  // Arithmetic to placeholder comparison is an invalid transitive join condition.
  $e2.principal.port + 800 = $port

```