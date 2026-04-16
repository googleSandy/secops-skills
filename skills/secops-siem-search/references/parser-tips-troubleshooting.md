# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/parser-tips-troubleshooting

# Tips and troubleshooting when writing parsers
Supported in:    Google secops   SIEM
This document describes issues you might encounter when you write parser code.
When writing parser code, you might encounter errors when parsing instructions don't work as expected. Situations that might generate errors include the following:  A `Grok` pattern fails A `rename` or `replace` operation fails Syntax errors in parser code
## Common practices in parser code
The following sections describe the best practices, tips, and solutions to help troubleshoot issues.
### Avoid using dots or hyphens in variable names
The use of hyphens and dots in variable names can cause unexpected behavior, often when performing `merge` operations to store values in UDM fields. You may also encounter intermittent parsing issues.
For example, do not use the following variable names:  `my.variable.result` `my-variable-result`
Instead, use the following variable name: `my_variable_result`.
### Do not use terms with special meaning as a variable name
Certain words, like `event` and `timestamp`, can have special meaning in parser code.
The string `event` is often used to represent a single UDM record and is used in the `@output` statement. If a log message includes a field called `event`, or if you define an intermediate variable called `event`, and the parser code uses the word `event` in the `@output` statement, you will get an error message about a name conflict.
Rename the intermediate variable to something else, or use the term `event1` as a prefix in UDM field names and in the `@output` statement.
The word `timestamp` represents the created timestamp of the original raw log. A value set in this intermediate variable is saved to the `metadata.event_timestamp` UDM field. The term `@timestamp` represents the date and time the raw log was parsed to create a UDM record.
The following example sets the `metadata.event_timestamp` UDM field to the date and time the raw log was parsed.
```
 # Save the log parse date and time to the timestamp variable
  mutate {
     rename => {
       "@timestamp" => "timestamp"
     }
   }

```
The following example sets the `metadata.event_timestamp` UDM field to the date and time extracted from the original raw log and stored in the `when` intermediate variable. Note: Not shown in this example are the statements that extract the date and time from the original raw log into the `when` intermediary field and transform the value to the correct format.
```
   # Save the event timestamp to timestamp variable
   mutate {
     rename => {
       "when" => "timestamp"
     }
   }

```
Don't use the following terms as variables:  collectiontimestamp createtimestamp event filename message namespace output onerrorcount timestamp timezone
### Store each data value in a separate UDM field
Do not store multiple fields in a single UDM field by concatenating them with a delimiter. The following is an example:
`"principal.user.first_name" => "first:%{first_name},last:%{last_name}"`
Instead, store each value in a separate UDM field.
```
"principal.user.first_name" => "%{first_name}"
"principal.user.last_name" => "%{last_name}"

```
### Use spaces rather than tabs in code
Do not use tabs in the parser code. Use only spaces and indent 2 spaces at a time.
### Do not perform multiple merge actions in a single operation
If you merge multiple fields in a single operation, this might lead to inconsistent results. Instead, place `merge` statements into separate operations.
For example, replace the following example:
```
mutate {
  merge => {
      "security_result.category_details" => "category_details"
      "security_result.category_details" => "super_category_details"
  }
}

```
With this:
```
mutate {
  merge => {
    "security_result.category_details" => "category_details"
  }
}

mutate {
  merge => {
    "security_result.category_details" => "super_category_details"
  }
}

```
### Choosing `if` versus `if else` conditional expressions
If the conditional value you are testing can only ever have a single match, then use the `if else` conditional statement. This approach is slightly more efficient. However, if you have a scenario where the tested value could match more than once, use multiple distinct `if` statements and order the statements from the most generic case to the most specific case.
### Choose a representative set of log files to test parser changes
A best practice is to test parser code using raw log samples with a broad variety of formats. This lets you find unique logs or edge cases that the parser might need to handle.
### Add descriptive comments to parser code
Add comments to parser code that explain why the statement is important, rather than what the statement does. The comment helps anyone maintaining the parser to follow the flow. The following is an example:
```
# only assign a Namespace if the source address is RFC 1918 or Loopback IP address
if [jsonPayload][id][orig_h] =~ /^(127(?:\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\{3\}$)|(10(?:\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\{3\}$)|(192\.168(?:\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\{2\}$)|(172\.(?:1[6-9]|2\d|3[0-1])(?:\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\{2\}$)/ {
  mutate {
    replace => {
      "event1.idm.read_only_udm.principal.namespace" => "%{resource.labels.project_id}"
    }
  }
}

```
### Initialize intermediate variables early
Before extracting values from the original raw log, initialize intermediate variables that will be used to store test values.
This prevents an error being returned indicating that the intermediate variable does not exist.
The following statement assigns the value in the `product` variable to the `metadata.product_name` UDM field.
```
mutate{
  replace => {
    "event1.idm.read_only_udm.metadata.product_name" => "%{product}"
  }
}

```
If the `product` variable does not exist, then you get the following error:
```
"generic::invalid_argument: pipeline failed: filter mutate (4) failed: replace failure: field \"event1.idm.read_only_udm.metadata.product_name\": source field \"product\": field not set"

```
You can add an `on_error` statement to catch the error. The following is an example:
```
mutate{
  replace => {
    "event1.idm.read_only_udm.metadata.product_name" => "%{product}"
    }
  on_error => "_error_does_not_exist"
  }

```
The preceding example statement successfully catches the parsing error into a boolean intermediate variable, called `_error_does_not_exist`. It does not enable you to use the `product` variable in a conditional statement, for example `if`. The following is an example:
```
if [product] != "" {
  mutate{
    replace => {
      "event1.idm.read_only_udm.metadata.product_name" => "%{product}"
    }
  }
  on_error => "_error_does_not_exist"
}

```
The preceding example returns the following error because the `if` conditional clause does not support `on_error` statements:
```
"generic::invalid_argument: pipeline failed: filter conditional (4) failed: failed to evaluate expression: generic::invalid_argument: "product" not found in state data"

```
To solve this, add a separate statement block that initializes the intermediate variables before executing the extraction filter (`json`, `csv`, `xml`, `kv`, or `grok`) statements. The following is an example.
```
filter {
  # Initialize intermediate variables for any field you will use for a conditional check
  mutate {
    replace => {
      "timestamp" => ""
      "does_not_exist" => ""
    }
  }

  # load the logs fields from the message field
  json {
    source         => "message"
    array_function => "split_columns"
    on_error       => "_not_json"
  }
}

```
The updated snippet of parser code handles the multiple scenarios using a conditional statement to check whether the field exists. In addition, the `on_error` statement handles errors that may be encountered.
### Convert SHA-256 to base64
The following example extracts the SHA-256 value, encodes it in base64, converts the encoded data to a hexadecimal string, and then replaces specific fields with the extracted and processed values.
```
if [Sha256] != "" 
{
  base64
  {
  encoding => "RawStandard"
  source => "Sha256"
  target => "base64_sha256"
  on_error => "base64_message_error"
  }
  mutate
  {
    convert =>
    {
      "base64_sha256" => "bytestohex"
    }
    on_error => "already_a_string"
  }
  mutate
  {
    replace => 
  {
     "event.idm.read_only_udm.network.tls.client.certificate.sha256" => "%{base64_sha256}"
     "event.idm.read_only_udm.target.resource.name" => "%{Sha256}"
  }
  }
}

```
### Handle errors in parser statements
It is not uncommon for incoming logs to be in an unexpected log format or have badly formatted data.
You can build the parser to handle these errors. A best practice is add `on_error` handlers to the extraction filter, and then to test the intermediate variable before proceeding to the next segment of parser logic.
The following example uses the `json` extraction filter with an `on_error` statement to set the `_not_json` boolean variable. If `_not_json` is set to `true`, this means that the incoming log entry wasn't in valid JSON format and the log entry was not parsed successfully. If the `_not_json` variable is `false`, the incoming log entry was in valid JSON format.
```
 # load the incoming log from the default message field
  json {
    source         => "message"
    array_function => "split_columns"
    on_error       => "_not_json"
  }

```
You can also test whether a field is in the correct format. The following example checks whether `_not_json` is set to `true`, indicating that the log was not in the expected format.
```
 # Test that the received log matches the expected format
  if [_not_json] {
    drop { tag => "TAG_MALFORMED_MESSAGE" }
  } else {
    # timestamp is always expected
    if [timestamp] != "" {

      # ...additional parser logic goes here …

    } else {

      # if the timestamp field does not exist, it's not a log source
      drop { tag => "TAG_UNSUPPORTED" }
    }
  }

```
This ensures that parsing does not fail if logs are ingested with an incorrect format for the specified log type.
Use the `drop` filter with the `tag` variable so that the condition is captured in the Ingestion metrics table in BigQuery.  `TAG_UNSUPPORTED` `TAG_MALFORMED_ENCODING` `TAG_MALFORMED_MESSAGE` `TAG_NO_SECURITY_VALUE`
The `drop` filter stops the parser from processing the raw log, normalizing the fields, and creating a UDM record. The original raw log is still ingested to Google Security Operations and can be search using raw log search in Google SecOps.
The value passed to the `tag` variable is stored in the `drop_reason_code`' field in the Ingestion metrics table. You can run an ad hoc query against the table similar to the following:
```
SELECT
  log_type,
  drop_reason_code,
  COUNT(drop_reason_code) AS count
FROM `datalake.ingestion_metrics`
GROUP BY 1,2
ORDER BY 1 ASC

```
### Troubleshoot validation errors
When building a parser, you may encounter errors related to validation, for example a required field is not set in the UDM record. The error may look similar to the following:
```
Error: generic::unknown: invalid event 0: LOG_PARSING_GENERATED_INVALID_EVENT: "generic::invalid_argument: udm validation failed: target field is not set"

```
The parser code executes successfully, but the generated UDM record does not include all required UDM fields as defined by value set to the `metadata.event_type`. The following are additional examples that may cause this error:  If the `metadata.event_type` is `USER_LOGIN` and the `target.user value` UDM field is not set. If the `metadata.event_type` is `NETWORK_CONNECTION` and the `target.hostname`UDM field is not set.
For more information about the `metadata.event_type` UDM field and required fields, see the UDM usage guide.
One option for troubleshooting this type of error is to start by setting static values to UDM fields. After you define all UDM fields needed, examine the original raw log to see which values to parse and save to the UDM record. If the original raw log does not contain certain fields, you may need to set default values. Note: You can't submit a parser with only static values because each UDM record can have the same data. However, this approach is helpful when troubleshooting UDM validation errors.
The following is an example template, specific to a `USER_LOGIN` event type, that illustrates this approach.
Notice the following:  The template initializes intermediate variables and sets each to a static string. The code under the Field Assignment section sets the values in intermediate variables to UDM fields.
You can expand this code by adding additional intermediate variables and UDM fields. After you identify all UDM fields that must be populated, do the following:
Under the Input Configuration section, add code that extracts fields from the original raw log and sets the values to the intermediate variables.
Under the Date Extract section, add code that extracts the event timestamp from the original raw log, transforms it, and sets it to the intermediate variable.
As needed, replace the initialized value set in each intermediate variable to an empty string.
```
filter {
 mutate {
   replace => {
     # UDM > Metadata
     "metadata_event_timestamp"    => ""
     "metadata_vendor_name"        => "Example"
     "metadata_product_name"       => "Example SSO"
     "metadata_product_version"    => "1.0"
     "metadata_product_event_type" => "login"
     "metadata_product_log_id"     => "12345678"
     "metadata_description"        => "A user logged in."
     "metadata_event_type"         => "USER_LOGIN"

     # UDM > Principal
     "principal_ip"       => "192.168.2.10"

     # UDM > Target
     "target_application"            => "Example Connect"
     "target_user_user_display_name" => "Mary Smith"
     "target_user_userid"            => "mary@example.com"

     # UDM > Extensions
     "auth_type"          => "SSO"
     "auth_mechanism"     => "USERNAME_PASSWORD"

     # UDM > Security Results
     "securityResult_action"         => "ALLOW"
     "security_result.severity"       => "LOW"

   }
 }

 # ------------ Input Configuration  --------------
  # Extract values from the message using one of the extraction filters: json, kv, grok

 # ------------ Date Extract  --------------
 # If the  date {} function is not used, the default is the normalization process time

  # ------------ Field Assignment  --------------
  # UDM Metadata
  mutate {
    replace => {
      "event1.idm.read_only_udm.metadata.vendor_name"        =>  "%{metadata_vendor_name}"
      "event1.idm.read_only_udm.metadata.product_name"       =>  "%{metadata_product_name}"
      "event1.idm.read_only_udm.metadata.product_version"    =>  "%{metadata_product_version}"
      "event1.idm.read_only_udm.metadata.product_event_type" =>  "%{metadata_product_event_type}"
      "event1.idm.read_only_udm.metadata.product_log_id"     =>  "%{metadata_product_log_id}"
      "event1.idm.read_only_udm.metadata.description"        =>  "%{metadata_description}"
      "event1.idm.read_only_udm.metadata.event_type"         =>  "%{metadata_event_type}"
    }
  }

  # Set the UDM > auth fields
  mutate {
    replace => {
      "event1.idm.read_only_udm.extensions.auth.type"        => "%{auth_type}"
    }
    merge => {
      "event1.idm.read_only_udm.extensions.auth.mechanism"   => "auth_mechanism"
    }
  }

  # Set the UDM > principal fields
  mutate {
    merge => {
      "event1.idm.read_only_udm.principal.ip"                => "principal_ip"
    }
  }

  # Set the UDM > target fields
  mutate {
    replace => {
      "event1.idm.read_only_udm.target.user.userid"             =>  "%{target_user_userid}"
      "event1.idm.read_only_udm.target.user.user_display_name"  =>  "%{target_user_user_display_name}"
      "event1.idm.read_only_udm.target.application"             =>  "%{target_application}"
    }
  }

  # Set the UDM > security_results fields
  mutate {
    merge => {
      "security_result.action" => "securityResult_action"
    }
  }

  # Set the security result
  mutate {
    merge => {
      "event1.idm.read_only_udm.security_result" => "security_result"
    }
  }

 # ------------ Output the event  --------------
  mutate {
    merge => {
      "@output" => "event1"
    }
  }

}

```
## Parse unstructured text using a Grok function
When using a Grok function to extract values from unstructured text, you can use predefined Grok patterns and regular expression statements. Grok patterns make code easier to read. If the regular expression does not include shorthand characters (such as `\w`, `\s`), you can copy and paste the statement directly into the parser code.
Because Grok patterns are an additional abstraction layer in the statement, they may make troubleshooting more complex when you encounter an error. The following is an example Grok function that contains both predefined Grok patterns and regular expressions.
```
grok {
  match => {
    "message" => [
      "%{NUMBER:when}\\s+\\d+\\s%{SYSLOGHOST:srcip} %{WORD:action}\\/%{NUMBER:returnCode} %{NUMBER:size} %{WORD:method} (?P<url>\\S+) (?P<username>.*?) %{WORD}\\/(?P<tgtip>\\S+).*"
    ]
  }
}

```
An extraction statement without Grok patterns may be more performant. For example, the following example takes fewer than half the processing steps to match. For a potentially high volume log source, this is an important consideration.
### Understand differences between RE2 and PCRE regular expressions
Google SecOps parsers use RE2 as the regular expression engine. If you are familiar with PCRE syntax, you may notice differences. The following is one example:
The following is a PCRE statement: `(?<_custom_field>\w+)\s`
The following is a RE2 statement for parser code: `(?P<_custom_field>\\w+)\\s`
### Make sure to escape the escape characters
Google SecOps stores incoming raw log data in JSON encoded format. This is to ensure that character strings which appear to be regular expression shorthand are interpreted as the literal string. For example `\t` is interpreted as the literal string, rather than a tab character.
The following example is an original raw log and the JSON encoded format log. Notice the escape character added in front of each backslash character surrounding the term `entry`.
The following is the original raw log:
```
field=\entry\

```
The following is the log converted to JSON encoded format:
`field=\\entry\\`
When using a regular expression in parser code, you must add additional escape characters if you want to extract only the value. To match a backslash in the original raw log, use four backslashes in the extraction statement.
The following is a regular expression for parser code:
`^field=\\\\(?P<_value>.*)\\\\$`
The following is the generated result. The `_value` named group stores the term `entry`:
`"_value": "entry"`
When moving a standard regular expression statement into parser code, escape regular expression shorthand characters in the extraction statement. For example, change `\s` to `\\s`.
Leave regular expression special characters unchanged when double escaped in the extraction statement. For example, `\\` remains unchanged as `\\`.
The following is a standard regular expression:
```
^.*?\\\"(?P<_user>[^\\]+)\\\"\s(?:(logged\son|logged\soff))\s.*?\\\"(?P<_device>[^\\]+)\\\"\.$

```
The following regular expression is modified to function within parser code.
```
^.*?\\\"(?P<_user>[^\\\\]+)\\\"\\s(?:(logged\\son|logged\\soff))\\s.*?\\\"(?P<_device>[^\\\\]+)\\\"\\.$

```
The following table summarizes when a standard regular expression must include additional escape characters before including it in parser code.    Regular expression Modified regular expression for parser code Description of the change
```
\s
```
```
\\s
```
Shorthand characters must be escaped.
```
\.
```
```
\\.
```
Reserved characters must be escaped.
```
\\"
```
```
\\\"
```
Reserved characters must be escaped.
```
\]
```
```
\\]
```
Reserved characters must be escaped.
```
\|
```
```
\\|
```
Reserved characters must be escaped.
```
[^\\]+
```
```
[^\\\\]+
```
Special characters within a character class group must be escaped.
```
\\\\
```
```
\\\\
```
Special characters outside of a character class group or shorthand characters do not require an extra escape.
### Regular expressions must include a named capture group
A regular expression, such as `"^.*$"`, is valid RE2 syntax. However, in parser code it fails with the following error:
```
"ParseLogEntry failed: pipeline failed: filter grok (0) failed: failed to parse data with all match
patterns"

```
You must add a valid capture group to the expression. If you use Grok patterns, these include a named capture group by default. When using regular expression overrides, make sure to include a named group.
The following is an example regular expression in parser code:
```
"^(?P<_catchall>.*$)"

```
The following is the result, showing the text assigned to the `_catchall` named group.
`"_catchall": "User \"BOB\" logged on to workstation \"DESKTOP-01\"."`
### Use a catchall named group to start as you build out the expression
When building an extraction statement, start with an expression that catches more than you want. Then, expand the expression one field at a time.
The following example starts by using a named group (`_catchall`) that matches the entire message. Then, it builds the expression in steps by matching additional portions of the text. With each step, the `_catchall` named group contains less of the original text. Continue and iterate one step at a time to match the message until you no longer need the `_catchall` named group.    Step Regular expression in parser code Output of the `_catchall` named capture group      1
```
"^(?P<_catchall>.*$)"
```
```
User \"BOB\" logged on to workstation \"DESKTOP-01\".
```
2
```
^User\s\\\"(?P<_catchall>.*$)
```
```
BOB\" logged on to workstation \"DESKTOP-01\".
```
3
```
^User\s\\\"(?P<_user>.*?)\\\"\s(?P<_catchall>.*$)
```
```
logged on to workstation \"DESKTOP-01\".
```
Continue until the expression matches the entire text string.
### Escape shorthand characters in the regular expression
Remember to escape regular expression shorthand characters when using the expression in parser code. The following is an example text string and the standard regular expression that extracts the first word, `This`.
```
  This is a sample log.

```
The following standard regular expression extracts the first word, `This`. However, when you run this expression in parser code, the result is missing the letter `s`.    Standard regular expression Output of the `_firstWord` named capture group      `"^(?P<_firstWord>[^\s]+)\s.*$"` `"_firstWord": "Thi",`
This is because regular expressions in parser code require an additional escape character added to shorthand characters. In the previous example, `\s` must be changed to `\\s`.    Revised regular expression for parser code Output of the `_firstWord` named capture group      `"^(?P<_firstWord>[^\\s]+)\\s.*$"` `"_firstWord": "This",`
This applies only to the shorthand characters, such as `\s`, `\r`, and `\t`. Other characters, such as ``, do not need to be escaped further.
### Grok pattern to extract email addresses that start with a numeral
In customer-specific parsers and code snippet parser extensions, don't use an `EMAILADDRESS` Grok pattern to extract email addresses that start with a numeral. As a workaround, you can use the `DATA` Grok pattern and then apply a regular expression validation at the mapping stage.
### A complete example
This section describes the previous rules as an end-to-end example. Here's an unstructured text string, and the standard regular expression written to parse the string. Finally, it includes the modified regular expression that functions in parser code.
The following is the original text string.
```
User "BOB" logged on to workstation "DESKTOP-01".

```
The following is a standard RE2 regular expression that parses the text string.
```
^.*?\\\"(?P<_user>[^\\]+)\\\"\s(?:(logged\son|logged\soff))\s.*?\\\"(?P<_device>[^\\]+)\\\"\.$

```
This expression extracts the following fields.    Match group Character position Text string     Full match 0-53
```
User \"BOB\" logged on to workstation \"DESKTOP-01\".
```
Group `_user` 7-10
```
BOB
```
Group 2. 13-22
```
logged on
```
Group `_device` 40-50
```
DESKTOP-01
```
This is the modified expression. The standard RE2 regular expression was modified to function in parser code.
```
^.*?\\\"(?P<_user>[^\\\\]+)\\\"\\s(?:(logged\\son|logged\\soff))\\s.*?\\\"(?P<_device>[^\\\\]+)\\\"\\.$

```