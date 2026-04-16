# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/transition_spl_yaral

# Transition from SPL to YARA-L 2.0
Supported in:    Google secops   SIEM
This guide is intended for users who are already familiar with Splunk Search Processing Language (SPL). It provides a quick introduction to YARA-L 2.0: the core language for building searches, dashboards, and detection rules within Google Security Operations.
## Understand the YARA-L 2.0 structure
YARA-L 2.0 is the unified query language used across Google SecOps for powerful threat searching, building real-time dashboards, and creating high-fidelity detection rules on all your enterprise log data as it's ingested.
The language works in conjunction with the Google SecOps Detection Engine and lets you search for threats and other events across large volumes of data.
### Basic structure differences between SPL and YARA-L
SPL uses a series of commands chained together with pipe (`|`) characters, whereas YARA-L is section-based. You define a query using distinct sections—such as `events`, `outcome`, and `condition`—to describe a pattern you want to search, detect, or visualize.
The following table compares the basic structure between SPL and YARA-L:    Function SPL (procedural) YARA-L (declarative)     Core concept Transform a stream of data step-by-step using a pipeline of commands. Analyzes and applies a multipart structure of conditions and transformations to a stream of security and operational data, identifying threats and extracting valuable insights.   Data flow Procedural. Results from one command are piped as input to the next.  Declarative structure to optimally process and correlate patterns at massive scale. Removing the need to think about efficiency.   Event correlation Relies on explicit commands like `join`, `transaction`, and `stats`. Built-in by defining multiple events and correlating them based on a common field within the query's logic.   Time windowing Handled as a static search window (for example, `last 60m`). Each new search is a fresh request. Handled as a continuous, sliding time window defined within the query (for example, `over 5m`).   Syntax Command-driven (for example, `index=web`). Concise and logic-driven (for example, `metadata.event_type= "USER_LOGIN"`).
### Specific structure of queries
YARA-L enforces a specific structure for queries, which is different from the sequential, piped (`|`) commands of SPL. While SPL builds results by chaining commands, YARA-L defines different aspects of the query in distinct sections.
Every YARA-L query or rule is segmented into distinct, named sections, which dictate the query's behavior. This structure is what enables multistage analysis and correlation.    Command Action Optional | Required     `meta` Sets descriptive metadata for the rule, such as author, description, and severity. Optional for Search and Dashboards. Required only for Rules.   `events` Defines and filters events. Declares all data sources (primarily UDM events) to consider and filters them using UDM fields. Lear more about the [`events` section syntax](/chronicle/docs/yara-l/events-syntax). Required (core logic of the query) for Search, Dashboards, and Rules.   `match` Groups by events and lets you specify the supported time window (for example, `by 5m`). Learn more about the [`match` section syntax](https://docs.cloud.google.com/chronicle/docs/yara-l/match-syntax). Optional for statistical searches where aggregation occurs. Required only for multi-event correlation queries. Time specification is required for rules and optional for Search and Dashboards.   `outcome` Calculates essential metrics and gets insights (for example, `count()`, `avg()`). Learn more about the [`outcome` section syntax](/chronicle/docs/yara-l/outcome-syntax). Optional.   `condition` Defines the logic that must be met to either return results (in Search) or trigger an alert (in a rule). Evaluates the query variable criteria to determine if a result applies (for example, `event > 5`). Learn more about the [`condition` section syntax](/chronicle/docs/yara-l/condition-syntax). Optional in Search and Dashboards. Required only for Rules.   `dedup` Removes duplicate events by grouping them based on essential variables (for example, `target.user.userid`, `target.ip`, `principal.hostname`). Learn more about how to [use deduplication in Search and Dashboards](/chronicle/docs/investigation/deduplication-yaral). Optional. Not available in Rules.   `order` Sorts results for collected events defined by specific fields (for example, `asc`). Optional (only applicable when `match` is used). Not available in Rules.   `limit` Restricts the maximum number of returned events from the query. Optional (only applicable when match is used). Not available in Rules.   `select` Specifies the list of UDM fields to include in the query results. Optional. Not available in Rules.   `unselect` Specifies the list of UDM fields to exclude from the query results. Optional. Not available in Rules.
## Common commands in SPL and YARA-L
The YARA-L section structure lets you use the same common commands found in SPL. This section outlines the similarities and differences.
### SPL `search` command = YARA-L `events` section
The `search` command in SPL is equivalent to the `events` section in YARA-L. The `events` section defines the events and how they're initially filtered. While other sections (like `match` or `outcome`) are optional, the `events` section is fundamental to every rule. Note: You don't need to declare "`events:`" in search and dashboards, but the section header is required in rules.
For example:
```
metadata.event_type = "USER_LOGIN"

```
or:
```
principal.hostname != "" AND metadata.event_type = "NETWORK_CONNECTION"

```
In the `events` section of rules (and advanced queries), you use event variables to simplify your logic.
An event variable acts as a logical grouping of filters, representing a specific event or a group of events that match certain criteria.
For example, to define an event variable, such as `$e`, use it as a prefix all of related events and filters in the `events` section of your query. You can then use that variable in other sections of the query (like `match` or `outcome`) to reference that specific group of events and their data fields.
The most common application for event variables is within detection rules. The following example demonstrates how to use the event variable (`$e`) in a rule to group events and find the number of failed logins for a user within one day. The rule then triggers if it exceeds a defined threshold.
In the rule example, each event is defined with the event variable (`$e`). The `$e` variable is also referenced in `metadata.id` to link the rule metadata back to the defined events.
```
rule DailyFailedLoginAttempts {
 meta:
   author = "Alex"
   description = "Detects a high number of failed login attempts for a single user within a day."

events:
   // Alias for each event
   $e.metadata.event_type = "USER_LOGIN"
   $e.security_result.action = "FAIL"
   $e.principal.user.userid != ""
   $userid = $e.principal.user.userid

match:
   // Group events by principal.user.userid within a 24-hour window
   $userid over 1d

outcome:
   // Count the number of unique event IDs for each user per day
   $daily_failed_login_count = count($e.metadata.id)

condition:
   // Trigger a detection if the daily failed login count exceeds a threshold
   // You should adjust this threshold based on your environment's baseline.
   #e > 0
}

```
To make sure the rule triggers, you often need to check the count of the grouped events. You can specify a minimum count in the `condition` section using the event variable. For example, the condition (`#e > 0`) checks that at least one event matching the criteria exists.
### SPL `eval` command = YARA-L `outcome` section
The `eval` command is a fundamental SPL function used for manipulating and defining field values in search results.  Purpose: It calculates and defines new field values. Functionality: It evaluates mathematical, string, or boolean expressions. Result: The result of the evaluation either creates a new field or overwrites an existing field's value. Chaining: Multiple expressions can be chained together using a comma (for example, `| eval A=1, B=A+1`). Sequential processing: Expressions in a chain are processed sequentially, letting later calculations reference and build upon fields created or modified by earlier expressions.  Note: In YARA-L, this functionality is primarily handled by the `outcome` section, where you can define and calculate variables using similar functions.
The examples in the following table (and after) explain this command structure:    Function Description YARA-L Example     Boolean operators Used in the `events` and `condition`. See Use or in the condition section.
```

metadata.log_type != "" or
metadata.event_type = "NETWORK_DNS"
      
```
Calculated fields  Used in the `outcome` section.
```

metadata.event_type = "SCAN_NETWORK"
principal.hostname != ""
outcome:
  $id = metadata.id
  $host = principal.hostname
  $bytes = cast.as_int(network.sent_bytes)
  
```
Dynamic field name creation Used in the `outcome` section. See examples in Compare SPL to YARA-L.
#### Example: Create a new field that contains the result of a calculation
Using YARA-L, create a new field, `bytes`, in each event. Calculate the bytes by adding the values in the sent `bytes` field with the received `bytes` field.
```
metadata.event_type = "SCAN_NETWORK"
principal.hostname != ""
$host = principal.hostname

match:
  $host

outcome:
  $bytes = cast.as_int(sum(network.sent_bytes))

```
#### Example: Concatenate values from two fields
Use the period (`.`) character to concatenate the values in the `first_name` field with the values in the `last_name` field. Use quotation marks (`""`) to insert a space character between the two fields. When concatenating, the values are read as strings, regardless of the actual value.
In SPL, the query would look similar to this:
```
| eval full_name = first_name+" "+last_name

```
In YARA-L, the search query would look similar to this:
```
principal.user.first_name = $first_name
principal.user.last_name = $last_name

outcome:
   $full_name = strings.concat($first_name, " ", $last_name)

```
Note: Aside from a `stats` search, where you can use field names, in rules, you must use a placeholder variable in the `match` section. For details, see Match variables.
Using the failed login query example, the following example lets you find users who've had five (`5`) or more failed logins within 10 minutes (`10m`) of each other (using both event and placeholder variables):
```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
target.user.userid = $userid

match:
  $userid by 10m

outcome:
   $login_count= count(metadata.id)

condition:
   $login_count > 5

```
### SPL `where` command = YARA-L `condition` section
The SPL `where` command is equivalent to a mix of the `events`, `outcome`, or `condition` section in YARA-L. Using the `events` section, you can declare events and specify specific attributes for them (for example, `principal.hostname = "xyz"`). After you declare your events, you can use boolean operators, comparison operators, and aggregation function results (from the `outcome` section) to define the parameters that the events must meet for the query to return a result.
The following example demonstrates how to set a threshold condition on an aggregated count. The query is structured to count the total number of failed login events per user ID and then uses the `condition` section to output results only for users who have recorded five or more failed logins.
```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"

match:
  target.user.userid

outcome:
  // metadata.id counts all unique events associated with failed logins.
  $count = count(metadata.id)
  //metadata.id counts all unique events associated with blocked logins.

condition:
  $count > 5

```
### SPL `dedup` command = YARA-L `dedup` section
The SPL `dedup` command is equivalent to the `dedup` section in YARA-L. Use the `dedup` section to deduplicate any duplicate results specified by an event in the `events` section.
For example:
```
principal.hostname = "foo"

dedup:
   target.ip

```
Learn more about how to use deduplication in Search and Dashboards, particularly about performance guidelines.
### SPL `stats` command = YARA-L `match` or `outcome` section (or both)
In SPL, aggregation is typically handled by the `stats` family of commands, which specify the aggregation type (such as `count`, `distinct` `count`, `max`, `min`) and the `"group by"` field.
In YARA-L, the `match` and `outcome` sections jointly provide this capability:
Aggregation logic: The `match` section creates aggregations by defining the group of events to be considered (`match: $grouping_field by time`). The `outcome` section then defines the specific aggregate functions to calculate over that group (for example, `count()`, `min()`, `max()`).
Time windowing: The `match` section supports specifying a time window to group events. Use the `over` keyword (for rules) or `by` (for search and dashboards) (for example, `match: $userid by 1h`). This functionality is similar to SPL, such as `"timechart"`, `"streamstats"`, and `"eventstats"`. For more information, see Time windowing.
#### Example: Calculate sum of bytes grouped by principal hostname and target IP
The following example uses the `match` section to define an aggregation group based on the principal hostname and target IP address over a one-day time window. The resulting sum of the bytes sent is then calculated within the `outcome` section.
```
metadata.event_type = "NETWORK_CONNECTION"
network.sent_bytes > 0
principal.hostname != ""
target.ip != ""

// Define placeholder variables for grouping
$principal_hostname = principal.hostname
$target_ip = target.ip

// Group events by principal hostname, target IP, and day
match:
  $principal_hostname, $target_ip by day

// Calculate the sum of sent bytes for each group
outcome:
  $daily_bytes_sent = sum(network.sent_bytes)

```
## Map SPL to YARA-L
SPL processes data step-by-step through piped commands, whereas YARA-L uses a declarative, section-based structure to define patterns and actions. Despite these fundamental differences in approach, the expressive power of YARA-L lets you perform many of the same tasks you're used to in SPL, from basic filtering to complex aggregations and correlations.
This section explains the differences by mapping familiar SPL functionalities to their equivalents within the YARA-L framework.
### Compare SPL to YARA-L
This table compares common functions and concepts in common SPL Language to their equivalents in YARA-L 2.0 or how the concept is handled within a YARA-L query structure.    SPL command or concept  Purpose  YARA-L equivalent  Description and YARA-L mapping YARA-L implementation example     `search` Initial data filtering `events` section Define event fields and conditions. No `events`: prefix needed for search or dashboards. See example.
```

events:
  metadata.event_type = "USER_LOGIN"
  security_result.action = "FAIL"

        
```
`where` Further filtering on results `events` and `condition` sections Apply boolean logic, often on aggregated outcomes. See example.
```

events:
  metadata.event_type = "USER_LOGIN"
  security_result.action = "FAIL"

outcome:
  $failed_count = count(metadata.id)

condition:
  $failed_count > 5
        
```
`eval` Computes new values from existing fields, aggregations, data lookups `outcome` or` events` section See example.
```

metadata.event_type = "USER_LOGIN"

outcome:
  $login_count = count(metadata.id)
        
```
`stats` Aggregations (`count`, `sum`, avg) `match` or `outcome` Group by fields in `match`. Calculate aggregates in `outcome`. See aggregation examples and SPL command examples.
```

metadata.event_type = "USER_LOGIN"

outcome:
  $login_count = count(metadata.id)
        
```
`dedup` Removes duplicate events based on one or more fields `dedup` section Specify fields to deduplicate on.
```

metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
$user = target.user.userid

dedup:
  $user
        
```
`table` Defines the table column output `select` or `unselect`  Used in dashboards. In search, displays `outcome` variables.
```

metadata.event_type = "USER_LOGIN"

select:
  principal.hostname
        
```
`sort` Lists results in ascending or descending order `order` section See example in the adjacent cell.
```
metadata.event_type = "SCAN_NETWORK"
principal.hostname != ""

outcome:
  $id = metadata.id
  $host = principal.hostname
  $bytes = uint64(network.sent_bytes)

order:
  $bytes desc

```
`limit`  Restricts the number of results returned `limit` section See example in the adjacent cell.
```

metadata.event_type = "SCAN_NETWORK"
principal.hostname != ""

outcome:
  $id = metadata.id
  $host = principal.hostname
  $bytes = cast.as_int(network.sent_bytes)

order:
  $bytes desc

limit:
  3
  
```
Multi-value functions Handled with `mv*`functions (`mvexpand`, `mvfilter`) Built-in support YARA-L automatically unnests arrays in the events section.  Array functions are available in `outcome`, if needed.  See multivalue function examples.   Time windowing `earliest=-5m, latest=now` `match` section, `over`, `by` For continuous detections, use `match: $field over 5m or by 5m`. For dashboards in the Search UI, use `match: $field by 5m`.  See examples in Time windowing.
### Aggregation and statistical queries
In YARA-L, aggregation and statistical functions are typically placed in the `outcome` section, and the aggregation is based in the `match` section.
The `stats` command is the primary mechanism for implementing data aggregation within the YARA-L queries. It transforms raw event data into summarized security metrics. While the `eval` command handles field-level, row-by-row transformations (similar to a `SELECT` expression), `stats` performs set-level aggregation (similar to `GROUP BY` in SQL).
The following table provides the core syntax and usage, demonstrating how to effectively use stats to implement sophisticated security logic based on data patterns and statistical outliers.    SPL function Description YARA-L equivalent YARA-L implementation example     `count` Counts the number of events. `count()`
```

metadata.event_type= "USER_LOGIN"
security_result.action= "FAIL"

outcome:
  $event_count = count(metadata.id)

condition:
  $event_count > 2
  
```
`dc (count_distinct)` Counts the number of unique values for a field. `count_distinct()`
```

metadata.event_type = "USER_LOGIN"

outcome:
  $unique_users=count_distinct(principal.user.userid)
  
```
`sum` Calculates the sum of values for a field.  `sum()`
```

metadata.event_type = "SCAN_NETWORK"
principal.hostname != ""
$host = principal.hostname

match:
  $host

outcome:
  $bytes = sum(network.sent_bytes)
  
```
`avg` Calculates the average value for a field.  `avg()`
```

$host = principal.hostname

match:
  $host by day

outcome:
  $avg_bytes_sent = avg(network.sent_bytes)
  
```
`min/max` Finds the minimum or maximum value for a field. `min()` or `max()`
```

metadata.event_type = "SCAN_NETWORK"
principal.hostname != ""
$host = principal.hostname

match:
  $host

outcome:
  $bytes = max(network.sent_bytes)- min(network.sent_bytes)
  
```
`median()` Finds the median value. `window.median`
```

target.file.mime_type = "PDF"

outcome:
  $median_file_size = window.median(target.file.size, false)
  
```
`first() and last()` Returns values based on the order of events in the search results. `window.first/window.last`
```

metadata.event_type = "NETWORK_CONNECTION"
principal.ip != ""

match:
  principal.ip

outcome:
  $event_count = count(metadata.id)
  $first_seen = window.first(metadata.event_timestamp.seconds, timestamp.get_timestamp(metadata.event_timestamp.seconds))
  $last_seen = window.last(metadata.event_timestamp.seconds, timestamp.get_timestamp(metadata.event_timestamp.seconds))
  
```
`STDDEV()` Calculates the standard deviation, which measures the dispersion of a dataset. `window.stddev`
```

principal.hostname= $host

match:
  $host over 5m

outcome:
  $stddev = window.stddev(network.sent_bytes)
```
For details, see additional functions.
For example, a multistage query can track multiple failed logins across layered aggregations. For details, see the multistage aggregation example and Create multistage queries in YARA-L.
### Multistage aggregation (hourly-to-weekly average)
This multistage example initially aggregates the data to find the bytes transferred per host each hour. It then uses that aggregation to calculate the overall average across those hourly buckets for the last seven days.
```
stage bytes_per_host {
metadata.event_type = "SCAN_NETWORK"
principal.hostname != ""
$host = principal.hostname

match:
  $host by hour

outcome:
  $bytes = cast.as_int(sum(network.sent_bytes))
}

$host = $bytes_per_host.host

match:
  $host

outcome:
  $hour_buckets = array_distinct(timestamp.get_timestamp($bytes_per_host.window_start))
  $num_hour_buckets = count_distinct($bytes_per_host.window_start)
  $avg_hourly_bytes = avg($bytes_per_host.bytes)

```
### Multivalue functions (read an array)
YARA-L's syntax is built to understand that a field can have multiple values. When you write a query that includes an event with multivalued field in the `events` section, the language automatically checks every value in the array. You don't need to use a special function to filter the array; you just state the condition you want to match. For example, if the log event's `principal.ip` field contains the following, the YARA-L engine automatically checks every value in the `principal.ip` array. If any of the values are `"10.1.1.5"`, the condition is met.
```
["10.1.1.5", "10.2.2.6", "10.3.3.7"]

```
The following table shows a comparison between YARA-L and SPL on how to manage multivalue fields in log data. Multivalue fields, such as an array of IP addresses or a list of user groups, are a common feature in structured logs.    SPL function Purpose YARA-L equivalent YARA-L implementation example     `mvfilter()` Filters a multivalue field to keep only matching values. When used in the `events` section of a YARA-L query, list the field to match. YARA-L automatically checks if any value in the groups array matches `"admin"`.
```

principal.user.group_identifiers = "admin"
        
```
`mvcount()` Counts the number of values in a multivalue field. `count()` applied to a field in the `outcome` query section. No need to unnest any values first.  See the Count the amount of users that belong to IT staff group example.    `mvexpand` Creates a new event for each value in a multivalue field. Handles multivalue fields natively and implicitly; unnesting happens automatically. See the Count the amount of users that belong to IT staff group example.   `mvjoin` Joins all values from a multivalue field into a single string for data formatting purposes. The values are automatically stored as an array in the results. YARA-L's output is structured, not a flat string. It displays the field as an array if further manipulation of the array is needed. For details, use array functions.
#### Example: Count the number of `admin` logins
In the following example, the condition `$metadata.event_type = "USER_LOGIN"` filters for events where the event_type is `"USER_LOGIN"`:
```
events:
 metadata.event_type = "USER_LOGIN"
 // Changed to a more appropriate event type for login
 principal.user.group_identifiers = "admin"

outcome:
 // This counts each unique event ID where the principal user is in the `"admin"` group.
 $admin_login_count = count(metadata.id)

```
The `$principal.user.group_identifiers= "admin"` field is a repeated field (an array).  Implicit unnesting: YARA-L automatically unnests this field internally during query evaluation. Condition check: An event will satisfy the condition if any of the values within the `$principal.user.group_identifiers` array is equal to `"admin"`. No explicit command needed: Unlike SPL, you don't need a specific unnesting command like `mvexpand`.
The impact on aggregation (`outcome`) section means that the implicit unnesting is crucial in the `outcome` section (for example, `outcome: $admin_login_count = count(metadata.id))`. Note the following impact:  A single UDM event that contains multiple matching values in a repeated field can generate multiple internal rows for the purpose of query evaluation. Because the `events` section has already effectively unnested the events based on each matching value in `$principal.user.group_identifiers`, the `count(metadata.id)` aggregation counts each of these unnested instances.
#### Example: Count the amount of users that belong to IT staff group
SPL:
```
index=<your_index_name> user_id="jsmith"
| where match(memberOf, "Domain Admins|IT Staff|HR")
| mvexpand memberOf
| stats count by memberOf
| mvexpand actions
| table memberOf, count, actions

```
YARA-L (search):
```
 principal.user.userid = "jsmith"
 additional.fields["memberOf"] = $group
   $group = /Domain Admins|IT Staff|HR/ nocase

 match:
   $group by 1h

 outcome:
   $group_count = count_distinct(metadata.id)
   $memberOf = array_distinct($group)
   $risk_score = max(50)

```
#### Example: Create a rule to alert when a specific file hash is present
SPL:
```
| eval file_hashes="hash12345,hash67890,hashABCDE"
| makemv delim="," file_hashes
| mvexpand file_hashes
| search file_hashes="hash67890"
| table _time, file_hashes

```
YARA-L (rule):
```
    rule specific_file_hash_detected {

    meta:
      rule_name = "Specific File Hash Detected"
      description = "Detects events where a specific file hash is present."
      severity = "Medium"

    events:
      $e.target.file.sha256 = "hash67890"

    outcome:
      $time = array_distinct($e.metadata.event_timestamp.seconds)
      $file_hashes = array_distinct($e.target.file.sha256)

    condition:
      $e
    }

```
## Time windowing
In YARA-L, time windowing is a method for correlating events over a specific, rolling time period. When used in rules, this window continually moves with incoming data, which provides the continuous real-time detection of patterns that unfold over time.
This process is a key part of the design for automated detection and is one of the benefits in using YARA-L. By specifying the time window, your detections and dashboards continuously work with real-time data.    Feature SPL  YARA-L      Primary goal Static search, ad hoc analysis Continuous detection, automated correlation   Primary functions ` earliest, latest, span, transaction `  `over`, `by`   5-minute example `earliest=-5m` (static search) or ` transaction maxspan=5m ` `match`: `[event] over 5m` (continuous detection in rules) or ` [event] by 5m` (search and dashboards)
The examples in this section illustrate the difference between a tumbling time window (using `by`) and sliding time window (using `over`) in YARA-L.
### Tumbling time window (`by <time_unit>`)
Concept: Used in YARA-L search, tumbling windows create fixed, non-overlapping fixed-size time intervals. The system processes each event by assigning each one to exactly one specific time bucket based on its timestamp. These fixed intervals are absolute, and align strictly with standard time markers, such as days, hours, or minutes).
Usage: Commonly used in Google SecOps search queries and Dashboards to aggregate data into discrete time segments.
Example: Daily count of successful logins per user
This search query groups successful login events by each unique user within each calendar day. The following example demonstrates a YARA-L search tumbling window (`by day`):
```
events:
  //Filter for successful login events
  metadata.event_type = "USER_LOGIN"
  principal.user.userid != ""

match:
  //Group by each unique user ID, aggregated over a calendar day.
  principal.user.userid by day

outcome:
  //Count how many successful logins occurred for this user on this specific day.
  $daily_success_count = count(metadata.id)

  //Get the timestamp of the FIRST event within this daily group.
  $first_event_time = window.first(metadata.event_timestamp.seconds, timestamp.get_timestamp(metadata.event_timestamp.seconds))

  //Get the timestamp of the LAST event within this daily group.
  $last_event_time = window.last(metadata.event_timestamp.seconds, timestamp.get_timestamp(metadata.event_timestamp.seconds))

```
How it works: If user `jdoe` has 10 successful logins on `Nov 17` and 15 on `Nov 18`, this query produces two separate rows for `jdoe`, one for each day, with the respective counts. The `Nov 17` bucket includes events from `2025-11-17 00:00:00 to 23:59:59 UTC`.
### Sliding time window (`over <duration>`)
Concept: Used in YARA-L Rules, sliding windows are moving, potentially overlapping time windows of a specified duration. They're ideal for correlating events that happen within a certain proximity of each other.
Usage: Primarily used in YARA-L Rules to detect patterns or sequences of events within a continuous timeframe.
Example: Detect multiple failed logins within 5 minutes
This YARA-L Rule example generates a detection if a single user has more than `5 failed logins` attempts within any rolling `5-minute` period:
```
rule TooManyFailedLogins_SlidingWindow {
 meta:
   author = "Alex"
   description = "Detects when a user has more than 5 failed logins within a 5-minute sliding window."
   severity = "Medium"

events:
   // Define an event variable $e for failed login attempts
   $e.metadata.event_type = "USER_LOGIN"
   $e.security_result.action = "FAIL"
   $e.principal.user.userid != ""
   $userid = $e.principal.user.userid

match:
   // Group events by userid over a continuous 5-minute sliding window.
   // Any events for the same $userid within 5 minutes of each other are grouped.
   $userid over 5m

outcome:
   // Count the number of failed login events within each 5-minute window for the grouped userid.
   $failed_count = count($e.metadata.id)

condition:
   // Trigger a detection if the count of failed logins in ANY 5-minute window is greater than 5.
   #e > 5
}

```
How it works: The system continuously monitors for failed logins. At any given moment, it considers the last 5 minutes of events for each user. For example, if between `10:02:30` and `10:07:30`, user `jdoe` accumulates six failed logins, a detection is triggered. This window constantly slides forward, letting real-time pattern detection occur, regardless of calendar boundaries.