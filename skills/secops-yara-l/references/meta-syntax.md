# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/meta-syntax

# Meta section syntax
Supported in:    Google secops   SIEM
The `meta` section of a YARA-L rule is required and must appear at the start of the query. Note: The `meta` section is not used in search or dashboard queries.
This section can include multiple lines, where each line defines a key-value pair. The `key` is a string value without quotes, and the `value` is a string with quotes, such as: `<key> = "<value>"`
For example:
```
rule failed_logins_from_new_location {
  meta:
   author = "Security Team"
   description = "Detects multiple failed logins for a user from a new, never-before-seen IP address within 10 minutes."
   severity = "HIGH"

  ... rest of the rule ...
}

```