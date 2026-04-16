# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/reference-list-syntax

# Use reference lists and data tables in YARA-L 2.0
Supported in:    Google secops   SIEM
Reference lists and data tables let you structure your logic by comparing event fields against custom datasets. Use these objects to manage high-volume indicators—such as known-bad IPs or approved hostnames—across Search, Dashboards, and detections without modifying underlying syntax.
You can use reference lists or data tables in the `events` or `outcome` sections of a rule. See Reference lists and Use data tables for more information on reference list and data table behavior and syntax.
## Apply reference list and data table syntax
Reference lists and data tables follow a similar syntax, defined by the object ID and the type of matching (`string`, `regex`, or `CIDR`) required for the operation.. This section shows syntax examples for using various types of reference lists.
In Google Security Operations, reference lists and data tables are used within a YARA-L rule's `events` or `outcome` sections to compare event data against uploaded datasets. These are executed during the rule evaluation process to filter events or enrich detection results.
Use reference lists when you need to check if a single field matches any value in a predefined list (for example, a list of known malicious IPs).  STRING: `$e.principal.hostname in %string_list_name`
REGEX: `$e.principal.hostname in regex %regex_list_name`
CIDR: `$e.principal.ip in cidr %cidr_list_name`
Use data tables when your reference data has a row or column structure, letting you map specific fields to specific columns.
STRING: `$e.target.hostname in %table_name.column_name`
REGEX: `$e.target.hostname in regex %table_name.column_name`
CIDR: `$e.principal.ip in cidr %table_name.column_name`
### Examples: Reference list syntax and behavior
The following examples illustrate how to structure queries for different dataset types and apply conditional logic to your matches:
#### Example: Reference list syntax in a query
```

// STRING reference list
$e.principal.hostname in %string_reference_list

// Regular expression reference list
$e.principal.hostname in regex %regex_reference_list

// CIDR reference list
$e.principal.ip in cidr %cidr_reference_list

```
#### Example: Data table syntax
```

// STRING data table
$e.target.hostname in %data_table_name.column_name

// Regular expression data table
$e.target.hostname in regex %regex_table_name.column_name

// CIDR data table
$e.principal.ip in cidr %cidr_table_name.column_name

```
#### Example: `not` and `nocase` operators
The `nocase` operator is compatible with `STRING` lists and `REGEX` lists.
```

// Exclude events whose hostnames match substrings in my_regex_list.
not $e.principal.hostname in regex %my_regex_list

// Event hostnames must match at least one string in my_string_list (case insensitive).
$e.principal.hostname in %my_string_list nocase
    
```
The `nocase` operator is compatible with `STRING` lists and `REGEX` lists.
For performance reasons, the Detection Engine restricts reference list usage.  Maximum `in` statements in a rule, with or without special operators: 10 Maximum `in` statements with the `regex` operator: 5 Maximum `in` statements with the `cidr` operator: 5
For more information about reference list behavior and reference list syntax, see Reference Lists.
To maintain optimal performance across Search, Dashboards, and detections, the YARA-L engine enforces the following limits:  Maximum `in` statements in a query, with or without special operators: 7 Maximum `in` statements with the `regex` operator: 4 Maximum `in` statements with the `cidr` operator: 2