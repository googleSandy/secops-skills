# Source: https://docs.cloud.google.com/chronicle/docs/investigation/statistics-aggregations-in-udm-search

# YARA-L 2.0 aggregations and statistics
Supported in:    Google secops   SIEM
This page describes how to run statistical queries on UDM events and group the results for analysis using YARA-L 2.0.
When handling a large volume of UDM events generated in your environment, understanding the trends in your UDM search data is important. You can use statistics and aggregate functions to gain actionable insights from your UDM logs. UDM search supports all the aggregate functions in YARA-L 2.0. Note: Statistical queries for UDM events are available two hours after ingestion.
## Use cases for statistical queries
You can use statistical queries for the following use cases:
Track critical metrics: you can measure the distribution and frequency of UDM events and associated assets, such as hosts communicating with known malicious IP addresses.
Detect anomalous behaviour: you can identify activity spikes that may indicate security incidents, such as unexpected network traffic surges or logins during off-hours.
Analyze trends over time: you can assess security posture changes to evaluate control effectiveness or identify areas for improvement, such as monitoring fluctuations in vulnerability counts over time.
## YARA-L 2.0 query structure in search
You can group and order UDM search query results using syntax similar to the YARA-L structured used in detection engine rules. For more information, see Get started: YARA-L 2.0 in Google SecOps. Note: Your existing UDM queries will continue to work in Google Security Operations search.
The YARA-L 2.0 query structure is as follows:
Filtering statement: specifies the conditions to filter events.
Match (optional): defines the fields to group by. For more information, see Match section syntax.
Outcome: specifies the outputs of the query. For more information, see Outcome section syntax. Note: A query can have an outcome section without a match section.
Dedup (optional): reduces the volume of duplicate results. For more information, see Use deduplication in search and dashboards.
Order: determines the order of query results as `asc` (ascending) or `desc` (descending). If the order (`asc` or `desc`) is not specified, it defaults to `asc`.
Limit (optional): sets the maximum number of rows the query returns.
#### Example: Order and limit use
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
### array
```
array(expression)

```
#### Description
The `array` function returns all the values in the form of a list. It truncates the list to a maximum of 25 random elements.
#### Param data types
`STRING`
#### Return type
`LIST`
#### Code Samples
##### Example
Return an array containing event types.
```
  $event_type = metadata.event_type
  outcome:
    $event_type_array = array($event_type)

```
### array_distinct
```
array_distinct(expression)

```
#### Description
The `array_distinct` function returns all the distinct values in the form of a list. It truncates the list to a maximum of 25 random elements. The deduplication to get a distinct list is applied before truncation.
#### Param data types
`STRING`
#### Return type
`LIST`
#### Code Samples
##### Example
Return an array containing distinct event types.
```
  $event_type = metadata.event_type
  outcome:
    $event_type_array = array_distinct($event_type)

```
### avg
```
avg(numericExpression)

```
#### Description
The `avg` function returns the average of values within a numeric column. It ignores `NULL` values during the calculation. It is often used with `match` to calculate the averages within specific groups in the data.
#### Param data types
`NUMBER`
#### Return type
`NUMBER`
#### Code Samples
##### Example
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store the average of `metadata.event_timestamp.seconds` in a variable called `avg_seconds`.
```
  target.ip != ""
  match:
    principal.ip
  outcome:
    $avg_seconds = avg(metadata.event_timestamp.seconds)

```
### count
```
count(expression)

```
#### Description
The `count` function returns the number of rows within a group. It is often used with `match` to get counts for specific groups in the data.
#### Param data types
`STRING`
#### Return type
`NUMBER`
#### Code Samples
##### Example
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
### count_distinct
```
count_distinct(expression)

```
#### Description
The `count_distinct` function returns the number of rows that have distinct values within a group. It is often used with `match` to get counts for specific groups in the data.
#### Param data types
`STRING`
#### Return type
`NUMBER`
#### Code Samples
##### Example
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
.supported-container { display: flex; gap: 7px; }
### earliest
Supported in:    Dashboards   Rules   Search
```
earliest(timestamp)

```
#### Description
The `earliest` function returns the earliest timestamp from a set of records with microsecond resolution.
#### Param data types
`TIMESTAMP`
#### Return type
`TIMESTAMP`
#### Code sample
For all the events that match on `hostname`, store the earliest of `metadata.event_timestamp` in the `start` variable.
```
  $hostname = principal.hostname
  match:
    $hostname
  outcome:
    $start = earliest(metadata.event_timestamp)

```
.supported-container { display: flex; gap: 7px; }
### latest
Supported in:    Dashboards   Rules   Search
```
latest(timestamp)

```
#### Description
The `latest` function returns the latest timestamp from a set of records with microsecond resolution.
#### Param data types
`TIMESTAMP`
#### Return type
`TIMESTAMP`
#### Code sample
For all the events that match on `hostname`, store the latest of `metadata.event_timestamp` in the `end` variable.
```
  $hostname = principal.hostname
  match:
    $hostname
  outcome:
    $end = latest(metadata.event_timestamp)

```
### max
```
max(numericExpression)

```
#### Description
The `max` function returns the maximum of the values within a numeric column. It is often used with `match` to get the maximum value within each group in the data.
#### Param data types
`NUMBER`
#### Return type
`NUMBER`
#### Code Samples
##### Example
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store the maximum of `metadata.event_timestamp.seconds` in a variable called `max_seconds`.
```
  target.ip != ""
  match:
    principal.ip
  outcome:
    $max_seconds = max(metadata.event_timestamp.seconds)

```
### min
```
min(numericExpression)

```
#### Description
The `min` function returns the minimum of the values within a numeric column. It is often used with `match` to get the minimum value within each group in the data.
#### Param data types
`NUMBER`
#### Return type
`NUMBER`
#### Code Samples
##### Example
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store the minimum of `metadata.event_timestamp.seconds` in a variable called `min_seconds`.
```
  target.ip != ""
  match:
    principal.ip
  outcome:
    $min_seconds = min(metadata.event_timestamp.seconds)

```
### stddev
```
stddev(numericExpression)

```
#### Description
The `stddev` function returns the standard deviation over all the possible values.
#### Param data types
`NUMBER`
#### Return type
`NUMBER`
#### Code Samples
##### Example
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store the standard deviation of `metadata.event_timestamp.seconds` in a variable called `stddev_seconds`.
```
  target.ip != ""
  match:
    principal.ip
  outcome:
    $stddev_seconds = stddev(metadata.event_timestamp.seconds)

```
### sum
```
sum(numericExpression)

```
#### Description
The `sum` function returns the sum of values within a numeric column. It ignores `NULL` values during the calculation. It is often used with `match` to calculate the sums within different groups in the data.
#### Param data types
`NUMBER`
#### Return type
`NUMBER`
#### Code Samples
##### Example
Find all the events where `target.ip` is not empty. For all the events that match on `principal.ip`, store a sum of `network.sent_bytes` in a variable called `sent_bytes`.
```
  target.ip != ""
  match:
    principal.ip
  outcome:
    $sent_bytes = sum(network.sent_bytes)

```
## YARA-L 2.0: search compared to UDM
The `over` keyword, used for event window searches, isn't supported in search.
UDM search queries don't include the `condition` and `option` sections.  Note: Unlike UDM queries, search queries in Preview don't support dynamic inputs through the console. All placeholders in saved search queries are treated as YARA-L 2.0 variables.
## Group by time granularity
You can group event fields and placeholders in the `match` section by a specified time granularity, similar to grouping a column in SQL.
The syntax is as follows:
```
match:
  ... [BY|OVER EVERY] [FIRST] [NUMBER] [TIME_GRANULARITY]

```
To group by time granularity, you can either use the keyword `by` or `over every`. The allowed time granularities are as follows:  `MINUTE` or `m` `HOUR` or `h` `DAY` or `d` `WEEK` or `w` `MONTH` or `mo`
Both the `by` and the `over every` keywords are functionally equivalent. You can use one over the other.
#### Example: Group IP address and hostname by every two hours
```
$hostname = principal.hostname
match:
  $hostname, target.ip by 2h

```
#### Example: Group by hostname with full-time granularity
```
$hostname = principal.hostname
match:
  $hostname by minute

```
#### Example: Group all events by hostname and day the event occurred
```
$hostname = target.hostname
match:
  $hostname over every day
outcome:
  $events_count = count($hostname)

```
Some data sources, like the entity context, are valid over a time range (`<start_time>`, `<end_time>`) and don't have singular timestamps.
The `first` keyword is optional and it applies to a single timestamp. This means that for a data source valid over a time range, the keyword `first` considers only the start time (`<start_time>`).
For example, consider an entity with a time range of (`1m, 5m`) with a time granularity of `1m`. If the results are grouped by hosts (`h1`,`h2`), the returned columns will be (`h1`, `1m`) and (`h2`, `1m`), with the rest of the time range ignored.
The `first` keyword can be added to both `by` and `over every`, resulting in the same behavior for both. The use of `by first` is equivalent to `over every first`.
The following is an example of a query that uses the `by` operator with the entity context data source that is valid over a time range. In this query, the entire time range is considered because the `first` keyword is omitted.
```
graph.entity.hostname != ""
match:
  graph.entity.ip by hour
outcome:
  $min_seconds = min(graph.metadata.event_metadata.event_timestamp.seconds)

```
## Create and save visualizations in search
This section outlines the data visualization capabilities within Google SecOps Unified Data Model (UDM) search. This feature allows Security Operations Center (SOC) analysts to efficiently detect, investigate, and respond to threats by creating visualizations from search results and saving them to dashboards. Note: You must have the `chronicle.nativeDashboards.create` and the `chronicle.nativeDashboards.update` IAM permissions to create visualizations.
### Create and save visualizations to add to the dashboard
To create and save visualizations to add to the dashboard, do the following:
Write a YARA-L query with `match` and `outcome` sections.
Select a date range, and then click the Run Search to run the query. View the results on the Statistics and Visualize tabs.
On the Visualize tab, do the following: a. Select a chart type from the Chart type list. b. Adjust settings under Data Settings to customize the chart.
On the Add to dashboard screen, do the following: a. Enter a chart name, description, and time range. b. Choose to add the chart to an existing dashboard or create a new dashboard.
Click Add to Dashboard to add the chart to dashboard.
## Limitations
The following limitations apply to statistical query execution:  Queries can't process data older than 90 days (a 3-month lookback period). Statistical queries return a maximum of 10,000 results.