# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/repeated-fields

# Repeated fields
Supported in:    Google secops   SIEM
In the Unified Data Model (UDM), some fields are labeled as repeated, which indicates that they are lists of values or other types of messages. This document provides information about how to use expressions, placeholders, array indexing, and repeated messages for repeated UDM fields.
## Boolean expressions and repeated fields
Modified and unmodified boolean expressions can act on repeated fields.
Consider the following event:
```
event_original {
  principal {
    // ip is a repeated field
    ip: [ "192.0.2.1", "192.0.2.2", "192.0.2.3" ]

    hostname: "host"
  }
}

```
### Modified expressions
Use the `any` and `all` modifiers in expressions in repeated fields.
`any` - If any element of the repeated field satisfies the condition, the event as a whole satisfies the condition. For example:  `event_original` satisfies `any $e.principal.ip = "192.0.2.1"` `event_original` fails `any $e.repeated_field.field_a = "9.9.9.9"`
`all` - If all elements of the repeated field satisfy the condition, the event as a whole satisfies the condition. For example:  `event_original` satisfies `net.ip_in_range_cidr(all $e.principal.ip, "192.0.2.0/8")` `event_original` fails `all $e.principal.ip = "192.0.2.2"`   Note: To use `any` or `all` with a function, the modifier must precede the repeated field and not the function. For example, `re.regex(any $e.about.hostname, `server-[0-9]+`)` is valid while `any re.regex($e.about.hostname, `server-[0-9]+`)` is invalid.
When writing a condition with `any` or `all`, be aware that negating the condition with `not` may not have the same meaning as using the negated operator.
For example:  `not all $e.principal.ip = "192.168.12.16"` checks if not all IP addresses match `192.168.12.16`, meaning the query is checking at least one IP address doesn't match `192.168.12.16` `all $e.principal.ip != "192.168.12.16"` checks if all IP addresses don't match `192.168.12.16`, meaning the query is checking that no IP addresses match to `192.168.12.16`
Constraints:  `any` and `all` operators are only compatible with repeated fields (not scalar fields). `any` and `all` cannot be used to join two repeated fields. For example, `any $e1.principal.ip = $e2.principal.ip` is not valid. `any` and `all` operators are not supported with the reference list expression.
### Unmodified expressions
With unmodified expressions, each element in the repeated field is treated individually. If an event's repeated field contains n elements, then the query is applied on n copies of the event, where each copy has one of the elements of the repeated field. These copies are transient and not stored.
The rule is applied on the following copies:    event copy principal.ip principal.hostname     event_copy_1 "192.0.2.1" "host"   event_copy_2 "192.0.2.2" "host"   event_copy_3 "192.0.2.3" "host"
If any event copy satisfies all unmodified conditions on the repeated field, the event as a whole satisfies all the conditions. Therefore, if you have multiple conditions on a repeated field, then a single event copy must satisfy all of them. The following query examples use the preceding example dataset to demonstrate this behavior.
#### Example: Unmodified expressions
The following rule returns one match when run against the `event_original` example dataset, because `event_copy_1` satisfies all of the events predicates:
```

rule repeated_field_1 {
  meta:
  events:
    net.ip_in_range_cidr($e.principal.ip, "192.0.2.0/8") // Checks if IP address matches 192.x.x.x
    $e.principal.ip = "192.0.2.1"
  condition:
    $e
}

```
The following rule doesn't return a match when run against the `event_original` example dataset, because there's no event copy in `$e.principal.ip` that satisfies _all_ the event predicates.
```

rule repeated_field_2 {
  meta:
  events:
    $e.principal.ip = "192.0.2.1"
    $e.principal.ip = "192.0.2.2"
  condition:
    $e
}

```
Modified expressions on repeated fields are compatible with unmodified expressions on repeated fields because the element list is the same for each event copy. Consider the following rule:
```
rule repeated_field_3 {
  meta:
  events:
    any $e.principal.ip = "192.0.2.1"
    $e.principal.ip = "192.0.2.3"
  condition:
    $e
}

```
The rule is applied on the following copies:    event copy principal.ip any $e.principal.ip     event_copy_1 "192.0.2.1" ["192.0.2.1", "192.0.2.2", "192.0.2.3"]   event_copy_2 "192.0.2.2" ["192.0.2.1", "192.0.2.2", "192.0.2.3"]   event_copy_3 "192.0.2.3" ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
In this case, all copies satisfy `any $e.principal.ip = "192.0.2.1"` but only `event_copy_3` satisfies $e.principal.ip = "192.0.2.3". As a result, the event as a whole would match.
Another way to think about these expression types are:  Expressions on repeated fields which use `any` or `all` operate on the list in `event_original`. Expressions on repeated fields which don't use `any` or `all` operate on individual `event_copy_n` events.
## Placeholders and repeated fields
Repeated fields work with placeholder assignments. Similar to unmodified expressions on repeated fields, a copy of the event is made for each element. Using the same example of `event_copy`, the placeholder takes the value of the `event_copy_n`'s repeated field value, for each of the event copies where n is the event copy number. If the placeholder is used in the match section, this can result in multiple matches.
#### Example: Repeated field placeholder
The following example generates one match. The `$ip` placeholder is equal to `192.0.2.1` for `event_copy_1`, which satisfies the predicates in the rule. The match's event samples contain a single element, `event_original`.
```

// Generates 1 match.
rule repeated_field_placeholder1 {
  meta:
  events:
    $ip = $e.principal.ip
    $ip = "192.0.2.1"
    $host = $e.principal.hostname

  match:
    $host over 5m

  condition:
    $e
}

```
The following example generates three matches. The `$ip` placeholder is equal to different values, for each of the different `event_copy_n` copies. The grouping is done on `$ip` since it is in the match section. Therefore, you get three matches where each match has a different value for the `$ip` match variable. Each match has the same event sample: a single element, `event_original`.
```

// Generates 3 matches.
rule repeated_field_placeholder2 {
  meta:
  events:
    $ip = $e.principal.ip
    net.ip_in_range_cidr($ip, "192.0.2.0/8") // Checks if IP matches 192.x.x.x

  match:
    $ip over 5m

  condition:
    $e
}

```
Note: `any` and `all` cannot be used when assigning a repeated field to a placeholder variable or joining with a field of another event. For example, `any $e.principal.ip = $ip` is not valid.
### Outcomes using placeholders assigned to repeated fields
Placeholders are assigned to each element of each repeated field, not the entire list. When they're used in the `outcome` section, the outcome is calculated using only the elements that satisfied earlier sections.
Consider the following rule:
```
rule outcome_repeated_field_placeholder {
  meta:
  events:
    $ip = $e.principal.ip
    $ip = "192.0.2.1" or $ip = "192.0.2.2"
    $host = $e.principal.hostname

  match:
    $host over 5m

  outcome:
    $o = array_distinct($ip)

  condition:
    $e
}

```
There are four stages of execution for this rule. The first stage is event copying:    event copy $ip $host $e     event_copy_1 "192.0.2.1" "host" event_id   event_copy_2 "192.0.2.2" "host" event_id   event_copy_3 "192.0.2.3" "host" event_id
The events section will then filter out rows that don't match the filters:    event copy $ip $host $e     event_copy_1 "192.0.2.1" "host" event_id   event_copy_2 "192.0.2.2" "host" event_id
`event_copy_3` is filtered out because `"192.0.2.3"` does not satisfy `$ip = "192.0.2.1" or $ip = "192.0.2.2"`.
The `match` section will then group by match variables and the `outcome` section will perform aggregation on each group:    $host $o $e     "host" ["192.0.2.1", "192.0.2.2"] event_id
`$o = array_distinct($ip)` is calculated using `$ip` from the previous stage and not the event copying stage.
Finally, the `condition` section will filter each group. Since this rule just checks for the existence of $e, the row from earlier will produce a single detection.
`$o` does not contain all the elements from `$e.principal.ip` because not all the elements satisfied all the conditions in the events section. However, all the elements of `e.principal.ip` will appear in the event sample because the event sample uses `event_original`.
### Array indexing
You can perform array indexing on repeated fields. To access the n-th repeated field element, use the standard list syntax (elements are 0-indexed). An out-of-bounds element returns the default value.  `$e.principal.ip[0] = "192.168.12.16"` `$e.principal.ip[999] = ""` If there are fewer than 1000 elements, this evaluates to `true`.
Constraints:  An index must be a non-negative integer literal. For example, `$e.principal.ip[-1]` is not valid. Values that have an `int` type (for example, a placeholder set to `int`) don't count. Array indexing cannot be combined with `any` or `all`. For example, `any $e.intermediary.ip[0]` is not valid. Array indexing cannot be combined with map syntax. For example, `$e.additional.fields[0]["key"]` is not valid. If the field path contains multiple repeated fields, all repeated fields must use array indexing. For example, `$e.intermediary.ip[0]` is not valid because `intermediary` and `ip` are both repeated fields, but there is only an index for `ip`.
### Repeated messages
When a `message` field is repeated, an unintended effect is to reduce the likelihood of a match. This is illustrated in the following examples.
Consider the following event:
```
event_repeated_message {
  // about is a repeated message field.
  about {
    // ip is a repeated string field.
    ip: [ "192.0.2.1", "192.0.2.2", "192.0.2.3" ]

    hostname: "alice"
  }
  about {
    hostname: "bob"
  }
}

```
As stated for unmodified expressions on repeated fields, a temporary copy of the event is made for each element of the repeated field. Consider the following rule:
```
rule repeated_message_1 {
  meta:
  events:
    $e.about.ip = "192.0.2.1"
    $e.about.hostname = "bob"
  condition:
    $e
}

```
The rule is applied on the following copies:    event copy about.ip about.hostname     event_copy_1 "192.0.2.1" "alice"   event_copy_2 "192.0.2.2" "alice"   event_copy_3 "192.0.2.3" "alice"   event_copy_4 "" "bob"
The event does not match on the rule because there exists no event copy that satisfies all of the expressions.
#### Repeated messages and array indexing
Another unexpected behavior can occur when using array indexing with unmodified expressions on repeated message fields. Consider the following example rule which uses array indexing:
```
rule repeated_message_2 {
  meta:
  events:
    $e.about.ip = "192.0.2.1"
    $e.about[1].hostname = "bob"
  condition:
    $e
}

```
The rule is applied to the following copies:    event copy about.ip about[1].hostname     event_copy_1 "192.0.2.1" "bob"   event_copy_2 "192.0.2.2" "bob"   event_copy_3 "192.0.2.3" "bob"   event_copy_4 "" "bob"
Since `event_copy_1` satisfies all of the expressions in `repeated_message_2`, the event matches on the rule.
This can lead to unexpected behavior because rule `repeated_message_1` lacked array indexing and produced no matches while rule `repeated_message_2` used array indexing and produced a match.