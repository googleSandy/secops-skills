# Source: https://docs.cloud.google.com/chronicle/docs/investigation/search-syntax-reference

# Understand search syntax
Supported in:    Google secops   SIEM
This guide is for security analysts who want to configure search expressions (data values, escapes, operators, and so on) in the query editor of the SIEM Search page.
When writing YARA-L 2.0 or SQL search expressions in the Google Security Operations query editor, you must format your data values, operators, and string escape sequences according to the exact data type of the target UDM field. A search condition consists of a UDM field name, a comparison operator (`=`, `!=`, `>`, `<`, `<=`, `>=`), and a formatted data value.
## Format data values by data type
This section describes the following:
### Enumerated values (enums)
Enums must be written as uppercase text strings exactly matching valid UDM dictionary definitions, enclosed in double quotes (`"`), like in the following example:
```
metadata.event_type = "NETWORK_CONNECTION" security_result.action = "BLOCK" network.ip_protocol = "TCP"

```
### Boolean values
Boolean fields accept true or false (case-insensitive, no quotes required), like in the following example:
```
network.dns.response = true target.user.is_admin = false

```
### Integers and numeric values
Integers and port numbers are written as literal digits without double quotes, like in the following example:
```
target.port = 443 network.sent_bytes > 10485760

```
### Float and decimal values
For UDM fields of the float or double type, enter a decimal number or integer without double quotes, like in the following example:
```
security_result.about.asset.vulnerabilities.cvss_base_score = 9.8

```
### Text strings
Standard text values must be enclosed inside double quotes (`"`), like in the following example:
```
metadata.product_name = "Google Cloud VPC Flow Logs" target.asset.asset_id = "srv-prod-us-central1-a"

```
#### Case-insensitive matching (nocase)
By default, string comparisons in YARA-L 2.0 are case-sensitive. To match any combination of uppercase and lowercase characters, append the `nocase` operator directly at the end of the condition, like in the following example:
```
principal.hostname != "http-server" nocase principal.user.userid = "jdoe" nocase

```
#### String escaping (\ and ")
If a string literal contains backslashes or double quotes, you must escape those characters using a leading backslash (`\\`), like in the following example:  Use `\\` to match a literal backslash (`\\`).
Use `\"` to match a literal double quote (`"`).
Search for Windows file paths with escaped backslashes:
```
principal.process.file.full_path = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"

```
Search for command lines containing embedded double quotes:
```
target.process.command_line = "cmd.exe /c \"c:\\program files\\malicious.exe\""

```
### Regular expressions (RE2 syntax)
To search using regular expressions, enclose the regex pattern between forward slashes (`/ /`) instead of double quotes. Google SecOps uses the standard RE2 regular expression engine:
Match any principal IP within the 10.x.x.x range, like this:
```
principal.ip = /10\..*/

```
Search for the execution of PsExec with optional `.exe` extension, case-insensitive, like in the following example:
```
target.process.command_line = /\bpsexec(\.exe)?\b/ nocase

```
Match dynamic DNS hostnames following a numbered pattern, like in the following example:
```
principal.hostname = /dns-server-[0-9]+/ nocase

```
Tip: Avoid starting regular expressions with a wildcard (`/.*pattern/`), because this prevents index pruning and forces a slow, full-table scan. Anchor your expressions whenever possible (`/^pattern/`).Note: For more details about regular expressions, see the regular expressions page.
## Boolean logic and operator precedence
Combine multiple search conditions using `AND`, `OR`, and `NOT` operators. You can use parentheses `()` to explicitly group expressions and control evaluation precedence, as shown in the following examples:
Search for specific user login events on a sensitive host, like in the following example:
```
metadata.event_type = "USER_LOGIN" AND target.hostname = "finance-db-prod"

```
Use parentheses to isolate OR conditions from AND chains, like in the following example:
```
metadata.event_type = "PROCESS_LAUNCH" AND principal.process.file.full_path = /winword.exe/ nocase AND (target.process.file.full_path = /cmd.exe/ OR target.process.file.full_path = /powershell.exe/)

```
## Search for key-value pairs in `additional` and `labels` fields
The `additional` and `labels` fields serve as flexible containers for custom event data and third-party vendor attributes that don't map to standard UDM fields. Each entry stores a key-value pair:
`additional` fields: Can contain multiple key-value pairs per event (`additional.fields["key"] = "value"`).  Note: `additional.fields` only support string values in search.
`labels` fields: Can contain only a single key-value pair per event (`labels["key"] = "value"`).
### Exact key-value matching (field["key"] = "value")
Use bracket syntax to query a specific key and its corresponding string value directly, like in the following example:
```
additional.fields["pod_name"] = "kube-scheduler-prod" metadata.ingestion_labels["MetadataKeyDeletion"] = "startup-script"

```
### Advanced regex and non-string value matching in `additional` fields
If you need to query numeric/boolean values inside `additional` fields, or match keys and values using regular expressions, use the fully qualified protobuf field path:
Match any value string inside the additional container by regex:
```
additional.fields.value.string_value = /suspicious_payload_.*/ nocase

```
Match boolean or numeric values inside custom fields:
```
additional.fields.value.bool_value = true additional.fields.value.number_value > 500

```
Search across multiple dynamic keys matching a regex prefix:
```
additional.fields.key = /^myKeyNumber_.*/

```
Check whether a key exists regardless of value:
```
additional.fields["pod_name"] != ""

```
Use regular expressions and `nocase` directly with bracket syntax:
```
additional.fields["pod_name"] = /br/
additional.fields["pod_name"] = bar nocase

```
Combine multiple `additional.fields` key-value pairs using `AND`:
```
additional.fields["pod_name"] = "kube-scheduler" AND additional.fields["namespace"] = "kube-system"

```
## Search grouped fields
Grouped fields are aliases for groups of related UDM fields. You can use them to query multiple UDM fields at the same time without typing each field individually. Note: Grouped fields have a separate section in the Aggregations panel of the Results tab.Caution: Grouped UDM field searches typically take longer than single UDM field searches.
The following example shows how to enter a query to match the common UDM fields that might contain the specified IP address:
`ip = "1.2.3.4"`
You can match a grouped field using a regular expression and using the `nocase` operator. Reference lists are also supported. Grouped fields can also be used in combination with regular UDM fields as shown in the following example:
`ip = "5.6.7.8" AND metadata.event_type = "NETWORK_CONNECTION"`
### Types of grouped UDM fields
You can search across all of the following grouped UDM fields:     Grouped field name Associated UDM fields     `domain` `about.administrative_domain``about.asset.network_domain``network.dns.questions.name``network.dns_domain``principal.administrative_domain``principal.asset.network_domain``target.administrative_domain``target.asset.hostname``target.asset.network_domain``target.hostname`   `email` `intermediary.user.email_addresses``network.email.from``network.email.to``principal.user.email_addresses``security_result.about.user.email_addresses``target.user.email_addresses`   `file_path` `principal.file.full_path``principal.process.file.full_path``principal.process.parent_process.file.full_path``target.file.full_path``target.process.file.full_path``target.process.parent_process.file.full_path`   `hash` `about.file.md5``about.file.sha1``about.file.sha256``principal.process.file.md5``principal.process.file.sha1``principal.process.file.sha256``security_result.about.file.sha256``target.file.md5``target.file.sha1``target.file.sha256``target.process.file.md5``target.process.file.sha1``target.process.file.sha256`   `hostname` `intermediary.hostname``observer.hostname``principal.asset.hostname``principal.hostname``src.asset.hostname``src.hostname``target.asset.hostname``target.hostname`   `ip` `intermediary.ip``observer.ip``principal.artifact.ip``principal.asset.ip``principal.ip``src.artifact.ip``src.asset.ip``src.ip``target.artifact.ip``target.asset.ip``target.ip`   `namespace` `principal.namespace``src.namespace``target.namespace`   `process_id` `principal.process.parent_process.pid``principal.process.parent_process.product_specific_process_id``principal.process.pid``principal.process.product_specific_process_id``target.process.parent_process.pid``target.process.parent_process.product_specific_process_id``target.process.pid``target.process.product_specific_process_id`   `user` `about.user.userid``observer.user.userid``principal.user.user_display_name``principal.user.userid``principal.user.windows_sid``src.user.userid``target.user.user_display_name``target.user.userid``target.user.windows_sid`
## Add comments in a query
You can add comments inside the search editor to document complex hunting logic or temporarily disable conditions during testing:  Single-line comments: Prefix the comment text with two forward slashes (`//`). Everything after the slashes on that line is ignored. Multi-line block comments: Enclose the comment text inside `/*` and `*/`. Block comments can span across multiple lines.
Example:
```
metadata.event_type = "NETWORK_CONNECTION" AND
// Exclude approved corporate proxy traffic
target.ip != "192.0.2.100" AND
/* Uncomment the lines below when investigating specific lateral
   movement across subnet 10.240.0.0/16 */
// principal.ip = /10.240\..*/ AND
// network.sent_bytes > 5000000

```