# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/multievent-n-of

# Use N OF syntax with event variables
Supported in:    Google secops   SIEM
This document explains how to use the N OF syntax to write flexible and conditional logic within the `condition` section of your query.
The N OF syntax lets you combine multiple conditions, reducing the overall complexity of your query syntax:  Provides a way to specify that a minimum number of boolean expressions from a given list must evaluate to true. Avoids the need to specify every possible combination, reducing errors and effort.
## N OF syntax
The syntax for an N OF statement is a comma-separated list of boolean expressions expressed as follows:
`[expr1, expr2, … , exprN]` where `[expr1, expr2, … , exprN]`
The following sections show some variations of the N OF syntax.
### ANY OF
The following example checks if at least one expression in the list is true. This is the same as joining all expressions with `or`.
```
condition:
  ANY OF [$e1, #e2 > 5, $outcome1 = "FAILED"]

```
### ALL OF
If all the expressions in the following list are true, the example is true. This is the same as joining all expressions with `and`.
```
condition:
  ALL OF [$e1, $e2, $outcome1 = "SUCCESS"]

```
### N of X
This is evaluated to true if at least `N` expressions from the list are true.
```
condition:
  2 of [$e1, $e2 > 0, $e3, arrays.contains($outcome_ips, "1.2.3.4")]

```
## Example rule: flag sensitive file access
The following rule flags a user if they successfully sign in (`$e1`). The rule then checks if the session also meets one of two criteria: a sensitive file is accessed (`$e2`) or the total number of unique sensitive files accessed exceeds `3`.
```
rule MultiEventNOf {
  meta:
    author = "google-secops"
    description = "Detects user login followed by sensitive file access or multiple sensitive files."
  events:
    $e1.principal.user.userid = $user
    $e1.metadata.event_type = "USER_LOGIN"

    $e2.principal.user.userid = $user
    $e2.metadata.event_type = "FILE_OPEN"
    re.regex($e2.target.file.full_path, `^/cns/sensitive/`)

  match:
    $user over 1h
  outcome:
    $sensitive_file_count = count_distinct($e2.target.file.full_path)
  condition:
    $e1 and ANY OF [$e2, $sensitive_file_count > 3]
  }

```
## Example search: flag sensitive file access
The following example shows how you could reformat the example rule as a search query. Note: Use event variables when including an N OF comparison in a search query.
```
$e1.principal.user.userid = $user
$e1.metadata.event_type = "USER_LOGIN"
$e2.principal.user.userid = $user
$e2.metadata.event_type = "FILE_OPEN"
re.regex($e2.target.file.full_path, `^/cns/sensitive/`)

match:
  $user over 1h
outcome:
  $sensitive_file_count = count_distinct($e2.target.file.full_path)
condition:
  $e1 and ANY OF [$e2, $sensitive_file_count > 3]

```
## Known limitations
Required event existence: Expressions N OF syntax can't be unbounded. The existence of the event must be a requirement for the clause to be true (for example, `$e1` or `#e1 > 0`).
Variable type mixing: You can't combine non-UDM variables with UDM event variables within the same N OF list.
Window restriction: You can't use tumbling windows with N OF syntax.