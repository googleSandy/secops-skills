# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/expressions

# Expressions, operators, and other constructs
Supported in:    Google secops   SIEM
This document includes information to help you build YARA-L rules and queries using expressions.
## Boolean expressions
Boolean expressions are expressions with a boolean type, which includes comparison expressions, function expressions, and reference list or data table expressions. You can use boolean expressions in the `events` and `outcome` section in a YARA-L rule or query.
### Comparison expressions
Comparison expressions are expressions that apply a comparison operator to two expressions. Expressions can be event fields, variables, literals, or function expressions. Note: A compilation error occurs if both sides are literals.
#### Example: Comparison expressions
```
$e.source.hostname = "host1234"
```
```
$e.source.port < 1024
```
```
1024 < $e.source.port
```
```
$e1.source.hostname != $e2.target.hostname
```
```
$e1.metadata.collected_timestamp.seconds > $e2.metadata.collected_timestamp.seconds
```
```
$port >= 25
```
```
$host = $e2.target.hostname
```
```
"google-test" = strings.concat($e.principal.hostname, "-test")
```
```
"email@google.org" = re.replace($e.network.email.from, "com", "org")
```
### Function expressions
Some function expressions return a boolean value, which can be used as an individual predicate in the `events` section, such as:
`re.regex()`
`net.ip_in_range_cidr()`
#### Example: Function expressions
```
re.regex($e.principal.hostname, `.*\.google\.com`)
```
```
net.ip_in_range_cidr($e.principal.ip, "192.0.2.0/24")
```
### Reference list or data table
You can use reference lists or data tables in the `events` or `outcome` sections. See Reference lists and Use data tables for more information on reference list and data table behavior and syntax.
#### Example: Syntax for reference lists
The following examples show the syntax for various types of reference lists in a query:
```

// STRING reference list
$e.principal.hostname in %string_reference_list

// Regular expression reference list
$e.principal.hostname in regex %regex_reference_list

// CIDR reference list
$e.principal.ip in cidr %cidr_reference_list

```
####  Example: Syntax for data tables
```

// STRING data table
$e.target.hostname in %data_table_name.column_name

// Regular expression data table
$e.target.hostname in regex %regex_table_name.column_name

// CIDR data table
$e.principal.ip in cidr %cidr_table_name.column_name

```
#### Example: Use `not` and `nocase` in reference lists syntax
```
// Exclude events whose hostnames match substrings in my_regex_list.
not $e.principal.hostname in regex %my_regex_list

// Event hostnames must match at least 1 string in my_string_list (case insensitive).
$e.principal.hostname in %my_string_list nocase

```
The `nocase` operator is compatible with `STRING` lists and `REGEX` lists.
For performance reasons, reference list and data table usage has the following limitations:  Maximum `in` statements in a query, with or without special operators: 10 Maximum `in` statements with the `regex` operator: 5 Maximum `in` statements with the `cidr` operator: 5
### Logical expressions
You can use the logical `and` and `or` operators in the `events` section.
#### Example: Logical expressions
```
$e.metadata.event_type = "NETWORK_DNS" or $e.metadata.event_type = "NETWORK_DHCP"
```
```
($e.metadata.event_type = "NETWORK_DNS" and $e.principal.ip = "192.0.2.12") or ($e.metadata.event_type = "NETWORK_DHCP" and $e.principal.mac = "AB:CD:01:10:EF:22")
```
```
not $e.metadata.event_type = "NETWORK_DNS"
```
By default, the precedence order from highest to lowest is `not`, `and`, `or`. For example, "a or b and c" is evaluated as "a or (b and c)" when the operators `or` and `and` are defined explicitly in the expression.
In the `events` section, predicates are joined using the `and` operator if an operator is not explicitly defined. The order of evaluation may be different if the `and` operator is implied in the expression. Consider the following comparison expressions where `or` is defined explicitly and the `and` operator is implied.
```

$e1.field = "bat"
or $e1.field = "baz"
$e2.field = "bar"

```
It is interpreted as follows:
```

($e1.field = "bat" or $e1.field = "baz")
and ($e2.field = "bar")

```
Because `or` is defined explicitly, the surrounding predicates are grouped and evaluated first. The last predicate, `$e2.field = "bar"`. is joined implicitly using `and`. The result is that order of evaluation changes.   Note: There is a limit on the number of `and` and `or` values you can specify for a single query. This limit varies depending on the complexity of the query and the complexity of the data in your Google SecOps account. Contact your Google SecOps representative for information on alternatives to this type of query.
#### Data table lookups in logical expressions
When you use data table lookups (the `in %list` syntax) within the `events` section, the following syntax constraints apply:
Type exclusivity: You can't mix standard field comparisons (for example, `$field = "value"`) and data table lookups within the same logical block.
Operator restriction: Data table lookups can only be joined with other data table lookups using the `OR` operator. The `AND` operator isn't supported for these expressions.
Example: Invalid results in a syntax error
```
// Invalid: Mixing a field comparison with a data table lookup
($field = "value" OR $field in %list)

// Invalid: Using AND with data table lookups
($field_A in %list_A AND $field_B in %list_B)

```
Example: Valid example
```
// Valid: Multiple data table lookups joined by OR
($field in %list_A OR $field in %list_B)

```
If your logic requires both a standard field check and a data table lookup, you must define them as separate, independent predicates within the `events` section.
## Enumerated types
You can use the operators with enumerated types. It can be applied to rules to simplify and optimize (use operator instead of reference lists) the performance.
In the following example, 'USER_UNCATEGORIZED' and 'USER_RESOURCE_DELETION' correspond to 15000 and 15014, so the rule will look for all the listed events:
```
$e.metadata.event_type >= "USER_CATEGORIZED" and $e.metadata.event_type <= "USER_RESOURCE_DELETION"

```
## Nocase Modifier
To ignore capitalization in a comparison expression between string values or a regular expression, append `nocase` to the end of the expression as shown in the following examples.
#### Example: nocase modifier
```
$e.principal.hostname != "http-server" nocase
```
```
$e1.principal.hostname = $e2.target.hostname nocase
```
```
$e.principal.hostname = /dns-server-[0-9]+/ nocase
```
```
re.regex($e.target.hostname, `client-[0-9]+`) nocase
```
The `nocase` modifier cannot be used when the field type is an enumerated value. The following examples are invalid and will generate compilation errors:
```
$e.metadata.event_type = "NETWORK_DNS" nocase
```
```
$e.network.ip_protocol = "TCP" nocase
```
## Comments
Comments can be used in queries to provide more information. You use the forward slash character to indicate a comment:  For a single-line comment, use two forward slash characters (`// comment`). For a multi-line comment, use the one forward slash character and the asterisk character (`/* comment */`).
## Literals
YARA-L supports non-negative integers and floats, string, boolean, and regular expression literals. Literals are fixed values used in query conditions. YARA-L also uses other literal-like constructs, such as regular expressions (enclosed in forward slashes) for pattern matching and booleans (true/false) for logic.
### String literals
String literals are sequences of characters enclosed in double quotes (") or back quotes (`). The string is interpreted differently, depending on which quote type you use:  Double quotes ("hello\tworld"): Use for normal strings; escape characters must be included, where \t is interpreted as a tab. Back quotes (`hello\tworld`): Use when all characters are to be interpreted literally, where \t is not interpreted as a tab.
### Regular expression literals
For regular expression literals, you have two options:
If you want to use regular expressions directly without the `re.regex()` function, use `/regex/` for the regular expression literals.
If you want to use string literals as regular expression literals, use the `re.regex()` function. Note that for double quote string literals, you must escape back slash characters with back slash characters, which can look awkward.
The following examples show equivalent regular expressions:
`re.regex($e.network.email.from, `.*altostrat\.com`)`
`re.regex($e.network.email.from, ".*altostrat\\.com")`
`$e.network.email.from = /.*altostrat\.com/`
Google recommends using back quote characters for strings in regular expressions for easier readability.
## Operators
Operator Description   = equal/declaration   != not equal   < less than   <= less than or equal   > greater than   >= greater than or equal
## Understand using variables in YARA-L
In YARA-L, all variables use the syntax `$<variable name>`. This section describes the types of variables to use in YARA-L.
### Event variables
Event variables represent groups of events or entity events. You specify conditions for event variables in the `events` section using a name, event source, and event fields.
Event sources are `udm` (for normalized events) and `graph` (for entity events). If the source is omitted, `udm` is set as the default source.
Event fields are represented as a chain of .<field name> (for example, $e.field1.field2) and the field chains always start from the top-level source (UDM or Entity).
### Match variables
Match variables are used in the `match` section to group events based on common values within a specified time window.
They become grouping fields for the query, as one row is returned for each unique set of match variables (and for each time window). When the query finds a match, the match variable values are returned.
You specify what each match variable represents in the `events` section.
### Placeholder variables
You use placeholder variables to capture and store specific values from UDM event fields to be referenced and used throughout a query. You can use them for linking scattered events together, especially in multi-event queries. By assigning a common value (for example, a `userid` or `hostname`) to a placeholder, you can then use this placeholder in the `match` section to group events that share that value within a specified time window.
You define placeholder variables in the `events` section by assigning the value of a UDM field to a variable name prefixed with a `$` (for example, `$targetUser = $e.target.user.userid`).
You can also define placeholder variables in the following sections:  `condition` section to specify `match` conditions. `outcome` section to perform calculations, define metrics, or extract specific data points from the matched events. `match` section to group events by common values.  Note: Every placeholder variable must be mapped to an event field. For example, if you only reference the following placeholder in this single line in a query, it would fail to compile because `$var` is not bound to an event variable (`$e.field != $var`).
### Function-to-placeholder assignment
In YARA-L, function-to-placeholder assignment is the process of transforming UDM event data and storing the result for use throughout a rule. This action lets you perform calculations or data manipulations in the `events` section and reference those results in the `match`, `condition`, and `outcome` sections.
The following are core components:  Functions: Built-in operations that perform calculations or data transformations (such as string manipulation or math) on specific event fields. Placeholder variables: User-defined variables, prefixed with `$` (for example, `$user`, `$ip`), that act as containers. They store values extracted directly from events or generated by function outputs. Assignment: The logic that links a function’s output to a placeholder variable, making that transformed data accessible to the rest of the detection logic.
### Limitations
There are two limitations when using a function-to-placeholder assignment:
You must assign every placeholder to an expression that contains an event field.
Valid examples
```
$ph1 = $e.principal.hostname
$ph2 = $e.src.hostname

// Both $ph1 and $ph2 have been assigned to an expression containing an event field.
$ph1 = strings.concat($ph2, ".com")

```

```
$ph1 = $e.network.email.from
$ph2 = strings.concat($e.principal.hostname, "@gmail.com")

// Both $ph1 and $ph2 have been assigned to an expression containing an event field.
$ph1 = strings.to_lower($ph2)

```
Invalid example
```
$ph1 = strings.concat($e.principal.hostname, "foo")
$ph2 = strings.concat($ph1, "bar") // $ph2 has NOT been assigned to an expression containing an event field.

```
The function call should depend on exactly one event. However, more than one field from the same event can be used in function call arguments.
Valid example
`$ph = strings.concat($event.principal.hostname, "string2")`
`$ph = strings.concat($event.principal.hostname, $event.src.hostname)`
Invalid example
`$ph = strings.concat("string1", "string2")`
`$ph = strings.concat($event.principal.hostname, $anotherEvent.src.hostname)`
## Use keywords to define queries
In YARA-L, keywords are reserved words that define the structure and logic of a detection query. They are used to specify different sections of a query, perform logical and mathematical operations, and define conditions for matching events. These keywords cannot be used as identifiers for queries, strings, or variables.
Keywords are not case-sensitive (for example, `and` or `AND` are equivalent).
### Key categories of YARA-L 2.0 keywords
This list is not exhaustive but covers the primary keywords used in YARA-L 2.0 for constructing robust detection queries.  Query definition:  `rule`: Initiates the definition of a new YARA-L query. `private`: Designates a query as private, preventing it from being directly exposed or triggered externally. `global`: Marks a query as global, indicating it should be applied broadly.   Query sections:  `meta`: Introduces the metadata section for descriptive information about the query. `strings`: Denotes the section where string patterns are defined. `condition`: Specifies the section containing the boolean logic for query triggering. `events`: Defines the section for specifying event variables and their conditions. `match`: Introduces the section for aggregating values over a time window. `outcome`: Defines the section for adding context and scoring to triggered queries.   String modifiers:  `ascii`: Specifies that a string should be matched as ASCII text. `wide`: Indicates that a string should be matched as wide (UTF-16) characters. `nocase`: Performs a case-insensitive string match. `fullword`: Requires the string to match as a complete word. `xor`: Applies XOR transformation to the string before matching. `base64`, `base64wide`: Applies Base64 encoding before matching.   Logical operators:  `and`, `or`, `not`: Standard boolean logical operators for combining conditions. `all of`, `any of`: Used for evaluating multiple expressions within a condition.   Comparison and relational operators:  `at`: Specifies an exact offset for string matching. `contains`: Checks if a string contains a substring. `startswith`, `endswith`: Checks if a string starts or ends with a substring. `icontains`, `istartswith`, `iendswith`, `iequals`: Case-insensitive versions. `matches`: Used for regular expression matching.   Data types and size specifiers:  `int8`, `uint8`, `int16`, `uint16`, `int32`, `uint32`: Integer types with specified sizes. `int8be`, `uint8be`, `int16be`, `uint16be`, `int32be`, `uint32be`: Big-endian versions of integer types. `filesize`: Represents the size of the file being analyzed. `entrypoint`: Refers to the entry point of an executable.
## YARA-L map support
YARA-L supports maps for the `Struct` and `Label` data types, which are used in some UDM fields.
To search for a specific key-value pair in both Struct and Label data types, use the standard map syntax:  Struct field syntax: `$e.udm.additional.fields["pod_name"] = "kube-scheduler"` Label field syntax: `$e.metadata.ingestion_labels["MetadataKeyDeletion"] = "startup-script"`  Note: The `FindingVariable` structure holds the value and associated metadata for values extracted while producing a finding.
#### Example: Valid and invalid use of maps
The following examples show valid and invalid use of maps.
#### Valid use of maps
Using a Struct field in the events section:
```

events:
  $e.udm.additional.fields["pod_name"] = "kube-scheduler"
  
```
Using a Label field in the outcome section:
```

outcome:
  $value = array_distinct($e.metadata.ingestion_labels["MetadataKeyDeletion"])
 
```
Assigning a map value to a Placeholder:
```

$placeholder = $u1.metadata.ingestion_labels["MetadataKeyDeletion"]

```
Using a map field in a join condition:
```

// using a Struct field in a join condition between two udm events $u1 and $u2
$u1.metadata.event_type = $u2.udm.additional.fields["pod_name"]

```
#### Unsupported use of maps
Combining `any` or `all` keywords with a map
```

all $e.udm.additional.fields["pod_name"] = "kube-scheduler"

```
Other types of values
Map syntax can only return a string value. In the case of [Struct](https://developers.google.com/protocol-buffers/docs/reference/google.protobuf#struct) data types, the map syntax can only access keys whose values are strings. Accessing keys whose values are other primitive types like integers, is not possible.
### Duplicate value handling in maps
Map access is intended to retrieve a single value associated with a specific key. This is the standard and expected behavior. However, in rare and uncommon situations, the context of the `map access` might inadvertently point to multiple values. In the uncommon edge case that map access refers to multiple values, the `map access` will deterministic return the first value. This can happen if a label has a duplicate key or a label has an ancestor repeated field.
#### Label has a duplicate key
The label structure represents a map, but does not enforce key uniqueness. By convention, a map should have unique keys, so Google SecOps does not recommend populating a label with duplicate keys.
#### Example: Label with duplicate key
The query text `$e.metadata.ingestion_labels["dupe-key"]` would return the first possible value, `val1`, if run over the following data example:
```

    // Disrecommended usage of label with a duplicate key:
    event {
      metadata{
        ingestion_labels{
          key: "dupe-key"
          value: "val1" // This is the first possible value for "dupe-key"
        }
        ingestion_labels{
          key: "dupe-key"
          value: "val2"
        }
      }
    }
  
```
#### Label has an ancestor repeated field
A repeated field might contain a label as a child field. Two different entries in the top-level repeated field might contain labels that have the same key.
#### Example: Label with ancestor repeated field
The query text `$e.security_result.rule_labels["key"]` would return the first possible value, `val3`, if run over the following data example:
```

    event {
      // security_result is a repeated field.
      security_result {
        threat_name: "threat1"
        rule_labels {
          key: "key"
          value: "val3" // This is the first possible value for "key"
        }
      }
      security_result {
        threat_name: "threat2"
        rule_labels {
          key: "key"
          value: "val4"
        }
      }
    }
  
```
### Access outcome variables in maps
This section explains how to access outcome variables within maps as their original data types (for example, integers, booleans, or lists of these types) rather than just strings. You can use this functionality for more flexibility and accuracy for your query logic.
Outcome data is available in the following fields:  Outcome values retain their original types in the `variables` field. The `outcomes` field stores `string` versions for backward compatibility.
You can access these outcome values using the `variables` map to retrieve the specific type or access elements in a sequence using array indexing. You can either access a specific item in the sequence by its index or select the entire sequence to evaluate each value individually.
Syntax:
```
$d.detection.detection.variables[OUTCOME_NAME].TYPE_SUFFIX
```
Syntax for sequences:
```
$d.detection.detection.variables[OUTCOME_NAME].SEQUENCE_TYPE_SUFFIX.TYPE_VALS_SUFFIX
```
#### Examples: Access outcome variables in maps
Access a string outcome:
```

    $my_string_outcome = $d.detection.detection.variables["outcome_ip"].string_val
   
```
This example retrieves the string value directly (for example, `"1.1.1.1"` if `outcome_ip` was a single string).
Access an integer outcome
```

    $my_int_outcome = $d.detection.detection.variables["outcome_port"].int64_value
    
```
This example retrieves the integer value (for example, `30`).
Access a list of integers using Int64Sequence
```

   $my_int_list = $d.detection.detection.variables["outcome_ports"].int64_seq.int64_vals
   
```
This example retrieves the full list of integers and unnests them like repeated fields (for example, `[2, 3, 4]`).
Access a specific element from a list of integers
```

    $first_int = $d.detection.detection.variables["outcome_ports"].int64_seq.int64_vals[0]
    
```
This example retrieves the first integer from the list (for example, `2`).
Access a list of strings (StringSequence)
```

    $my_string_list = $d.detection.detection.variables["outcome_ips"].string_seq.string_vals
    
```
This example retrieves the full list of strings and unnests them like repeated fields (for example, `["1.1.1.1", "2.2.2.2"]`).
Access a specific element from a list of strings
```

    $first_ip = $d.detection.detection.variables["outcome_ips"].string_seq.string_vals[0]
    
```
This example retrieves the first IP address from the list (for example, `"1.1.1.1"`).
### Available type suffixes for `variables`
For a full list of supported suffixes, see FindingVariable. Note: For backward compatibility, the original `outcomes` field continues to return array outcomes as comma-separated strings in existing queries.