# Source: https://docs.cloud.google.com/chronicle/docs/investigation/statistics-aggregations-in-udm-search

# Analyze search data with statistics
Supported in:    Google secops   SIEM
This page describes how to run statistical queries on UDM events and group the results for analysis using YARA-L 2.0.
When handling a large volume of UDM events generated in your environment, understanding the trends in your UDM search data is important. You can use statistics and aggregate functions to gain actionable insights from your UDM logs. UDM search supports all the aggregate functions in YARA-L 2.0. Note: Statistical queries for UDM events become available after ingestion processing completes, which introduces a delay before recent events appear in statistical query results.
## Use cases for statistical queries
You can use statistical queries for the following use cases:
Track critical metrics: you can measure the distribution and frequency of UDM events and associated assets, such as hosts communicating with known malicious IP addresses.
Detect anomalous behaviour: you can identify activity spikes that may indicate security incidents, such as unexpected network traffic surges or logins during off-hours.
Analyze trends over time: you can assess security posture changes to evaluate control effectiveness or identify areas for improvement, such as monitoring fluctuations in vulnerability counts over time.
## YARA-L 2.0 query structure in search
You can group and order UDM search query results using syntax similar to the YARA-L structured used in detection engine rules. For more information, see Get started: YARA-L 2.0 in Google SecOps. Note: Your existing UDM queries will continue to work in Google Security Operations search.
The YARA-L 2.0 query structure is as follows:
Filtering statement: specifies the conditions to filter events. For more information, see Filter missing, zero, and uninitialized values.
Match (optional): defines the fields to group by. For more information, see Match section syntax.
Outcome: specifies the outputs of the query. For more information, see Outcome section syntax. Note: A query can have an outcome section without a match section.
Dedup (optional): reduces the volume of duplicate results. For more information, see Use deduplication in search and dashboards.
Order: determines the order of query results as `asc` (ascending) or `desc` (descending). If the order (`asc` or `desc`) is not specified, it defaults to `asc`.
Limit (optional): sets the maximum number of rows the query returns.
Example: Order and limit use
The following example shows order and limit usage:
```
metadata.log_type = "OKTA"

match:
    principal.ip
Outcome:
    $user_count_by_ip = count(principal.user.userid)

order:
$user_count_by_ip desc

limit:
    20

```
## Aggregate functions
When events contain multiple values, you must use aggregate functions to summarize the data.
Search supports the following aggregate functions:
### `array`
The `array` function returns all the values in the form of a list. It truncates the list to a maximum of 25 random elements.    Syntax Param data types Return type     `array(expression)` `STRING` `LIST`
#### Code Sample
Return an array containing event types.
```
$event_type = metadata.event_type
outcome:
  $event_type_array = array($event_type)

```
### `array_distinct`
The `array_distinct` function returns all the distinct values in the form of a list. It truncates the list to a maximum of 25 random elements. The deduplication to get a distinct list is applied before truncation. Note: Missing or uninitialized Unified Data Model (UDM) fields default to zero values (such as `""`, `0`, or `"UNKNOWN_ACTION"`) instead of `NULL`. Because `array_distinct` treats zero values as valid data, it includes them in the returned list. For example, an outcome array containing only the empty string (`[""]`) displays as `[Unknown]` in your detection timeline. To remove default values from your array, add a filter in the `events` section of your query. When filtering repeated fields, use the `any` keyword (for example, `any $e.security_result.description != ""`) to preserve all array indexes during aggregation.    Syntax Param data types Return type     `array_distinct(expression)` `STRING` `LIST`
#### Code Samples
Return distinct event types
Return an array containing distinct event types.
```
$event_type = metadata.event_type
outcome:
  $event_type_array = array_distinct($event_type)

```
Exclude default values from distinct arrays
The following example filters out events that lack a security result description. It uses the any keyword on the repeated field to preserve all array indexes during outcome aggregation:
```
events:
  $e.security_result[0].description != ""
  any $e.security_result.description = ""
outcome:
  $security_result_description = array_distinct($e.security_result.description)

```
### `avg`
The `avg` function returns the average of values within a numeric column. It ignores `NULL` values during the calculation. It is often used with `match` to calculate the averages within specific groups in the data.    Syntax Param data types Return type     `avg(numericExpression)` `NUMBER` `NUMBER`
#### Code Sample
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store the average of `metadata.event_timestamp.seconds` in a variable called `avg_seconds`.
```
target.ip != ""
match:
  principal.ip
outcome:
  $avg_seconds = avg(metadata.event_timestamp.seconds)

```
### `count`
The `count` function returns the number of rows within a group. It is often used with `match` to get counts for specific groups in the data.    Syntax Param data types Return type     `count(expression)` `STRING` `NUMBER`
#### Code Sample
Return the count of successful user logins over time.
```
metadata.event_type = "USER_LOGIN"
$security_result = security_result.action
$security_result = "ALLOW"
$date = timestamp.get_date(metadata.event_timestamp.seconds, "America/Los_Angeles")
match:
    $security_result, $date
outcome:
    $event_count = count(metadata.id)

```
### `count_distinct`
The `count_distinct` function returns the number of rows that have distinct values within a group. It is often used with `match` to get counts for specific groups in the data. Note: Missing or uninitialized Unified Data Model (UDM) fields default to zero values (such as `""`, `0`, or `"UNKNOWN_ACTION"`) instead of `NULL`. Because `count_distinct` evaluates zero values as valid data, it counts them as unique items. If a field is uninitialized in some events, `count_distinct` counts the zero value as an additional distinct item, increasing your total count by one. To exclude default values from your count, add a filter in the `events` section of your query (for example, `$userid != ""`).    Syntax Param data types Return type     `count_distinct(expression)` `STRING` `NUMBER`
#### Code Samples
Return count of distinct user logins
Return the count of distinct successful user logins over time.
```
  metadata.event_type = "USER_LOGIN"
  $security_result = security_result.action
  $security_result = "ALLOW"
  $date = timestamp.get_date(metadata.event_timestamp.seconds, "America/Los_Angeles")
  match:
      $security_result, $date
  outcome:
      $event_count = count_distinct(metadata.id)

```
Exclude default values from distinct counts
The following example filters out uninitialized user IDs so `count_distinct` doesn't include default empty strings in the total count:
```
metadata.event_type = "USER_LOGIN"
$userid = principal.user.userid
$userid != ""
match:
    metadata.event_type
outcome:
    $distinct_users = count_distinct($userid)

```
### `earliest`
Supported in:    Dashboards   Rules   Search
The `earliest` function returns the earliest timestamp from a set of records with microsecond resolution.    Syntax Param data types Return type     `earliest(timestamp)` `TIMESTAMP` `TIMESTAMP`
#### Code sample
For all the events that match on `hostname`, store the earliest of `metadata.event_timestamp` in the `start` variable.
```
$hostname = principal.hostname
match:
  $hostname
outcome:
  $start = earliest(metadata.event_timestamp)

```
### `latest`
Supported in:    Dashboards   Rules   Search
The `latest` function returns the latest timestamp from a set of records with microsecond resolution.    Syntax Param data types Return type     `latest(timestamp)` `TIMESTAMP` `TIMESTAMP`
#### Code sample
For all the events that match on `hostname`, store the latest of `metadata.event_timestamp` in the `end` variable.
```
$hostname = principal.hostname
match:
  $hostname
outcome:
  $end = latest(metadata.event_timestamp)

```
### `max`
The `max` function returns the maximum of the values within a numeric column. It is often used with `match` to get the maximum value within each group in the data.    Syntax Param data types Return type     `max(numericExpression)` `NUMBER` `NUMBER`
#### Code Sample
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store the maximum of `metadata.event_timestamp.seconds` in a variable called `max_seconds`.
```
target.ip != ""
match:
  principal.ip
outcome:
  $max_seconds = max(metadata.event_timestamp.seconds)

```
### `min`
The `min` function returns the minimum of the values within a numeric column. It is often used with `match` to get the minimum value within each group in the data.    Syntax Param data types Return type     `min(numericExpression)` `NUMBER` `NUMBER`
#### Code Sample
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store the minimum of `metadata.event_timestamp.seconds` in a variable called `min_seconds`.
```
target.ip != ""
match:
  principal.ip
outcome:
  $min_seconds = min(metadata.event_timestamp.seconds)

```
### `stddev`
The `stddev` function returns the standard deviation over all the possible values.    Syntax Param data types Return type     `stddev(numericExpression)` `NUMBER` `NUMBER`
#### Code Sample
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store the standard deviation of `metadata.event_timestamp.seconds` in a variable called `stddev_seconds`.
```
target.ip != ""
match:
  principal.ip
outcome:
  $stddev_seconds = stddev(metadata.event_timestamp.seconds)

```
### `sum`
The `sum` function returns the sum of values within a numeric column. It ignores `NULL` values during the calculation. It is often used with `match` to calculate the sums within different groups in the data.    Syntax Param data types Return type     `sum(numericExpression)` `NUMBER` `NUMBER`
#### Code Sample
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store a sum of `network.sent_bytes` in a variable called `sent_bytes`.
```
target.ip != ""
match:
  principal.ip
outcome:
  $sent_bytes = sum(network.sent_bytes)

```
## Filter missing, zero, and uninitialized values
When you aggregate Unified Data Model (UDM) event data, your results might include unexpected empty strings, zero values, or `[Unknown]` entries. This happens because YARA-L 2.0 evaluates uninitialized fields as default zero values instead of `NULL`.
For example, uninitialized string fields default to an empty string (`""`), integer fields default to zero (`0`), and enumerated fields default to their unspecified value (such as `"UNKNOWN_ACTION"` for `principal.security_result.action`). Using zero values prevents negative comparison filters, such as `$e.principal.hostname != "test_domain"`, from accidentally excluding events that lack a hostname.
Because aggregate functions treat default zero values as valid data, this behavior affects your query results in the following ways:  Distinct counts: Functions such as `count_distinct` count default zero values as unique items. If a field is missing in some events, `count_distinct` counts the default zero value as an additional item, increasing your total count by one. Array lists: Functions such as `array` and `array_distinct` include default zero values in the returned lists. If an outcome array contains only the empty string (`[""]`), the detection timeline displays the value as `[Unknown]`.
To remove default values from your aggregations, add a filter in the `events` section of your query to exclude them (for example, `$e.field != ""`, `$e.field != 0`, or `$e.field != "UNKNOWN_ACTION"`).
When you filter repeated fields, prepend the filter with the `any` keyword, such as `any $e.security_result.description != ""`. Using `any` evaluates the condition across the entire event while preserving all array indexes when the outcome aggregates your data.
## YARA-L 2.0: search compared to UDM
The `over` keyword, used for event window searches, isn't supported in search.
UDM search queries don't include the `condition` and `option` sections. Note: Unlike UDM queries, search queries in Preview don't support dynamic inputs through the console. All placeholders in saved search queries are treated as YARA-L 2.0 variables.
For a detailed comparison between UDM search queries and live YARA-L 2.0 detection rules, see UDM search compared with rule results.
## Group by time granularity
You can group event fields and placeholders in the `match` section by a specified time granularity, similar to grouping a column in SQL.
The syntax is as follows:
Syntax format
```
match:
  ... [BY|OVER EVERY] [FIRST] [NUMBER] [TIME_GRANULARITY]

```
To group by time granularity, you can either use the keyword `by` or `over every`. The allowed time granularities are as follows:  `MINUTE` or `m` `HOUR` or `h` `DAY` or `d` `WEEK` or `w` `MONTH` or `mo`
Both the `by` and the `over every` keywords are functionally equivalent. You can use one over the other.
Example: Group IP address and hostname by every two hours
```
$hostname = principal.hostname
match:
  $hostname, target.ip by 2h

```
Example: Group by hostname with full-time granularity
```
$hostname = principal.hostname
match:
  $hostname by minute

```
Example: Group all events by hostname and day the event occurred
```
$hostname = target.hostname
match:
  $hostname over every day
outcome:
  $events_count = count($hostname)

```
### Group data sources over time ranges
Some data sources, like the entity context, are valid over a time range (`<start_time>`, `<end_time>`) rather than a single timestamp. When grouping by time granularity on these data sources, you can either evaluate the entire time range or restrict grouping to the start timestamp.
#### Evaluate the entire time range (default)
By default, if you omit the `first` keyword, the query evaluates the entire time range of the record.
Example: Group by entity IP address over a full time range
```
graph.entity.hostname != ""
match:
  graph.entity.ip by hour
outcome:
  $min_seconds = min(graph.metadata.event_metadata.event_timestamp.seconds)

```
#### Evaluate start timestamp using the first keyword
To restrict grouping to only the start timestamp (`<start_time>`) of a record, add the optional `first` keyword to your `match` statement. You can use `first` with either `by` or `over every` (`by first` is equivalent to `over every first`).
For example, consider an entity with a time range of `1m` to `5m` and a time granularity of `1m`. If results are grouped by hosts (`h1`, `h2`) using `first`, the returned columns will be (`h1`, `1m`) and (`h2`, `1m`), with the remainder of the time range ignored.
Example: Group by entity IP address using start time only
```
graph.entity.hostname != ""
match:
  graph.entity.ip by first hour
outcome:
  $min_seconds = min(graph.metadata.event_metadata.event_timestamp.seconds)

```
## Create and save visualizations in search
This section outlines the data visualization capabilities within Google SecOps Unified Data Model (UDM) search. This feature allows Security Operations Center (SOC) analysts to efficiently detect, investigate, and respond to threats by creating visualizations from search results and saving them to dashboards.
To create visualizations, you need the `chronicle.nativeDashboards.create` and `chronicle.nativeDashboards.update` IAM permissions.
### Create and save visualizations to add to the dashboard
To create and save visualizations to add to the dashboard, do the following:
Write a YARA-L query with `match` and `outcome` sections.
Select a date range, and then click the Run Search to run the query. View the results on the Statistics and Visualize tabs.
On the Visualize tab, do the following: a. Select a chart type from the Chart type list. b. Adjust settings under Data Settings to customize the chart.
On the Add to dashboard screen, do the following: a. Enter a chart name, description, and time range. b. Choose to add the chart to an existing dashboard or create a new dashboard.
Click Add to Dashboard to add the chart to dashboard.
## Limitations
The following limitations apply to statistical query execution:  Queries can't process data older than 90 days (a 3-month lookback period). Statistical queries return a maximum of 10,000 results.