# Source: https://docs.cloud.google.com/chronicle/docs/investigation/multi-stage-yaral

# Create multi-stage queries in YARA-L
Supported in:    Google secops   SIEM
This document describes how multi-stage queries in YARA-L let you feed the output of one query stage directly into the input of a subsequent stage. This process gives you greater control over data transformation than a single, monolithic query.
## Integrate multi-stage queries with existing features
Multi-stage queries work in conjunction with the following existing features in Google Security Operations:
Composite detection rules: Multi-stage queries complement composite detection rules by bridging the gap between automated detection and active investigation. While composite rules excel at identifying complex, multi-event correlations over extended time windows, multi-stage queries allow analysts to pivot from those detections into real-time, iterative searches to instantly validate and scope an unfolding threat.
Time ranges and multi-event rules: You can use multi-stage queries to detect anomalies by comparing different time windows within your data. For example, you can use your initial queries to establish a baseline over an extended period, and then use a later queries to evaluate recent activity against that baseline. You can also use multi-event rules to create a similar type of comparison.
Multi-stage queries in YARA-L are supported in both Dashboards and Search.
Joins help correlate data from multiple sources to provide more context for an investigation. By linking related events, entities, and other data, you can investigate complex attack scenarios. For more information, see Use joins in Search.
## Key considerations
As you configure a multi-stage query, be aware of the following:  Limit stage: Multi-stage queries must contain between one and four named stages, in addition to the root stage. Order syntax: Always define the named stage syntax before defining the root stage syntax.
We recommend that you review the following known issues and recommended workarounds when you implement multi-stage queries:
All multi-stage queries behave like statistics Search queries (the output consists of aggregated statistics rather than unaggregated events or data table rows).
The performance of joins with UDM and entity events on one side can experience low performance due to the size of that dataset. We strongly recommend filtering the UDM and entity events side of the join as much as possible (for example, filter on event type).
For general guidance on recommended practices, see YARA-L 2.0 best practices and for information specific to joins, see Best practices.
## Key terminology
In the context of joins, a windowed stage refers to a stage with a `match` section containing a window. In contrast, a table stage doesn't output windows.
## Create a multi-stage YARA-L query
To create a multi-stage YARA-L query, complete the following steps.
### Stage structure and syntax
Go to Investigation > Search. Follow this structure when you define your query stages:
Syntax: Use the following syntax to name each stage and separate it from other stages:
`stage <stage name> { }`
Braces: Place all stage syntax inside curly braces {}.
Order: Define the syntax for all named stages before defining the root stage.
Referencing: Each stage can reference stages defined earlier in the query.
Root stage: A query must have a root stage, which is processed after all named stages.
The following example stage, `daily_stats`, collects daily network statistics:
```
stage daily_stats {
  metadata.event_type = "NETWORK_CONNECTION"
  $source = principal.hostname
  $target = target.ip
  $source != ""
  $target != ""
  match:
    $source, $target by day
  outcome:
    $exchanged_bytes = sum(network.sent_bytes + network.received_bytes)
}

```
### Access stage output
The output of a named stage is accessible to subsequent stages using stage fields. Stage fields correspond with the stage's `match` and `outcome` variables and can be used similarly to Unified Data Model (UDM) fields.
Use the following syntax to access a stage field:
`$<stage name>.<variable name>`
### Optional: Access window timestamps
If a named stage uses a hop, sliding, or tumbling window, access the window start and window end for each output row using these reserved fields:
`$<stage name>.window_start`
`$<stage name>.window_end`
The `window_start` and `window_end` are integer fields expressed in seconds since the Unix epoch. Windows in different stages can vary in size.
### Multi-stage query examples
The examples in this section help to illustrate how you might create a complete multi-stage YARA-L query.
#### Example: Search for unusually active network connections (hours)
This multi-stage YARA-L example identifies IP address pairs with higher-than-normal network activity, targeting pairs that maintain high activity for more than three hours. The query includes two required components: the named stage, `hourly_stats`, and the `root` stage.
The `hourly_stats` stage searches for `principal.ip` and `target.ip` pairs with high levels of network activity.
This stage returns a single hourly value for following fields:
Statistics for the source IP (string): `$hourly_stats.src_ip`
Statistics for the destination IP (string): `$hourly_stats.dst_ip`
Statistics for the count of events (integer): `$hourly_stats.count`
Standard deviation received bytes (float): `$hourly_stats.std_recd_bytes`
Average received bytes (float): `$hourly_stats.avg_recd_bytes`
Hour bucket start time in seconds from the Unix epoch (integer): `$hourly_stats.window_start`
Hour bucket end time in seconds from the Unix epoch (integer): `$hourly_stats.window_end`
The root stage processes the output of the `hourly_stats` stage. It calculates statistics for `principal.ip` and `target.ip` pairs with activity exceeding the threshold specified by `$hourly_stats`. It then filters for pairs with more than three hours of high activity.
```

stage hourly_stats {
  metadata.event_type = "NETWORK_CONNECTION"
  $src_ip = principal.ip
  $dst_ip = target.ip
  $src_ip != ""
  $dst_ip != ""

  match:
    $src_ip, $dst_ip by hour

  outcome:
    $count = count(metadata.id)
    $avg_recd_bytes = avg(network.received_bytes)
    $std_recd_bytes = stddev(network.received_bytes)

  condition:
    $avg_recd_bytes > 100 and $std_recd_bytes > 50
}

$src_ip = $hourly_stats.src_ip
$dst_ip = $hourly_stats.dst_ip
$time_bucket_count = strings.concat(timestamp.get_timestamp($hourly_stats.window_start), "|", $hourly_stats.count)

match:
 $src_ip, $dst_ip

outcome:
 $list = array_distinct($time_bucket_count)
 $count = count_distinct($hourly_stats.window_start)

condition:
 $count > 3

```
If you alter the match condition in the root stage as follows, you can introduce a windowed aggregation by day for the multi-stage query.
```
match:
 $src_ip, $dst_ip by day

```
#### Example: Search for unusually active network connections (using Z-score)
This multi-stage query compares the daily average network activity against today's activity using a Z-score calculation (measuring the number of standard deviations away from the mean). This query effectively searches for unusually high network activity between internal assets and external systems.
Prerequisite: The query time window must be greater than or equal to 2 days and include the current day for the calculated Z-score to be effective.
This multi-stage query includes the `daily_stats` stage and the `root` stage, which work together to calculate the Z-score for network activity:
The `daily_stats` stage performs the initial daily aggregation. It calculates the total bytes exchanged each day for each IP pair (`source` and `target`) and returns the following stage fields (corresponding with columns in output rows):  `$daily_stats.source`: singular, string `$daily_stats.target`: singular, string `$daily_stats.exchanged_bytes`: singular, integer `$daily_stats.window_start`: singular, integer `$daily_stats.window_end`: singular, integer
The root stage aggregates the `daily_stats` stage output for each IP pair. It calculates the average and standard deviation of the daily bytes exchanged across the entire search range, along with the bytes exchanged today. It uses those three calculated values to determine the Z-score.
The output lists the Z-scores for all of today's IP pairs, sorted in descending order.
```
// Calculate the total bytes exchanged per day by source and target

stage daily_stats {
  metadata.event_type = "NETWORK_CONNECTION"
  $source = principal.hostname
  $target = target.ip
  $source != ""
  $target != ""

  match:
    $source, $target by day

  outcome:
    $exchanged_bytes = sum(network.sent_bytes + network.received_bytes)
}

// Calculate the average per day over the time window and compare with the bytes exchanged today

$source = $daily_stats.source
$target = $daily_stats.target
$date = timestamp.get_date($daily_stats.window_start)

match:
  $source, $target

outcome:
  $today_bytes = sum(if($date = timestamp.get_date(timestamp.current_seconds()), cast.as_int($daily_stats.exchanged_bytes), 0))
  $average_bytes = window.avg($daily_stats.exchanged_bytes)
  $stddev_bytes = window.stddev($daily_stats.exchanged_bytes)
  $zscore = ($today_bytes - $average_bytes) / $stddev_bytes

order:
  $zscore desc

```
## Export unaggregated variables from stages
In a typical multi-stage query, data is often passed between stages through an aggregation process, which can "collapse" multiple events into a single summary. However, there are scenarios where you need to preserve the specific details of every event—such as a unique process ID or a specific command line—without losing that granularity. To support this, you can export variables directly without a grouping function.
Named stages can include an unaggregated `outcome` section. This means that variables defined within that `outcome` section are output directly from the stage, letting subsequent stages access them as stage fields without requiring a grouped aggregation.
This detail is beneficial because it does the following:  Preserves data fidelity: You can pass the exact attributes of an event (for example, a specific file path) to the next stage without having to use an artificial "placeholder" aggregation like `max()` or `array_distinct()`. Reduces query complexity: It simplifies your YARA-L logic by removing the need for a `match` section or grouping statements just to transport a value from Stage 1 to Stage 2. Optimizes performance: By bypassing the aggregation engine, the system can stream data between stages more efficiently, leading to faster execution times for complex, high-volume searches.
#### Example: Export unaggregated variable
This example demonstrates how to export unaggregated variables. Note the following logic:
`top_5_bytes_sent` stage searches for the five events with the highest network activity.
`top_5_bytes_sent` stage outputs the following stage fields corresponding with columns in output rows:  `$top_5_bytes_sent.bytes_sent`: singular, integer `$top_5_bytes_sent.timestamp_seconds`: singular, integer
The `root` stage computes the latest and earliest timestamps for the five events with the highest network activity.
```
stage top_5_bytes_sent {
  metadata.event_type = "NETWORK_CONNECTION"
  network.sent_bytes > 0

  outcome:
    $bytes_sent = network.sent_bytes
    $timestamp_seconds = metadata.event_timestamp.seconds

  order:
    $bytes_sent desc

  limit:
    5
}

outcome:
  $latest_timestamp = timestamp.get_timestamp(max($top_5_bytes_sent.timestamp_seconds))
  $earliest_timestamp = timestamp.get_timestamp(min($top_5_bytes_sent.timestamp_seconds))

```
## Implement windowing in multi-stage queries
In multi-stage detections, windowing lets you define specific time boundaries for event correlation within a stage. By partitioning data into discrete temporal buckets, such as a 5-minute sliding window or a 1-hour tumbling window, you can identify patterns like brute-force attacks or beaconing behavior that only become visible when analyzed as a time-bound sequence.
Multi-stage queries support all types of windowing (hop, sliding, and tumbling) in named stages. This helps you pass time-contextualized data between stages, such as using Stage 1 to identify a high-frequency event window and Stage 2 to correlate that specific window against subsequent administrative actions.
If a named stage includes a window, the window start and window end for each output row is accessible using the following reserved fields:  `$stage_window_start`: The Unix timestamp marking the beginning of the window. `$stage_window_end`: The Unix timestamp marking the end of the window.
For more details about windowing, see YARA-L 2.0 windowing logic.
### Common use cases
Sequential detection: Passing the specific timeframe of a detected spike in failed logins to a second stage that looks for a successful login shortly thereafter. Duration analysis: Calculating the "time-to-compromise" by comparing the `$stage_window_start` of an initial exploit stage to the timestamps of events in a later stage. Historical baselining: Using windows to compare current event counts against a previous window's output variables.
### Example: Hop window
The following example illustrates how you might use hop windows in a multi-stage query:
`hourly_stats` stage searches for IP pairs that have high network activity within the same hour.
`hourly_stats` outputs the following stage fields corresponding with columns in output rows:  `$hourly_stats.src_ip`: singular, string `$hourly_stats.dst_ip`: singular, string `$hourly_stats.count`: singular, integer `$hourly_stats.std_recd_bytes`: singular, float `$hourly_stats.avg_recd_bytes`: singular, float `$hourly_stats.window_start`: singular, integer `$hourly_stats.window_end`: singular, integer
Root stage filters out IP pairs with more than 3 hours of high activity. The hours could be overlapping due to usage of a hop window in the `hourly_stats` stage.
```
stage hourly_stats {
  metadata.event_type = "NETWORK_CONNECTION"
  $src_ip = principal.ip
  $dst_ip = target.ip
  $src_ip != ""
  $dst_ip != ""

  match:
    $src_ip, $dst_ip over 1h

  outcome:
    $count = count(metadata.id)
    $avg_recd_bytes = avg(network.received_bytes)
    $std_recd_bytes = stddev(network.received_bytes)

  condition:
    $avg_recd_bytes > 100 and $std_recd_bytes > 50
}

$src_ip = $hourly_stats.src_ip
$dst_ip = $hourly_stats.dst_ip
$time_bucket_count = strings.concat(timestamp.get_timestamp($hourly_stats.window_start), "|", $hourly_stats.count)

match:
 $src_ip, $dst_ip

outcome:
 $list = array_distinct($time_bucket_count)
 $count = count_distinct($hourly_stats.window_start)

condition:
 $count > 3

```
## Inner joins in multi-stage queries
Inner joins lets you correlate data across different stages or source types, which creates complex analytical workflows, such as comparing real-time events against pre-computed statistical baselines. By joining stages, you can enrich raw telemetry with stateful data (like medians or lookup tables) to identify outliers or multi-vector threats that a single-stage event filter would miss.
Inner joins are supported within and between the stages of multi-stage queries. The inner join functionality supports the following types:  UDM and UDM: Correlating two different sets of security events (for example, matching a login event with a subsequent file access). UDM and ECG: Merging event data with Entity Context Graph information for identity or asset enrichment. UDM and datatable: Joining live events against static or uploaded reference lists (for example, a list of high-value assets or department-specific IP ranges).
The following example shows how to configure a matchless join (a join performed in the `outcome` or `events` section rather than the `match` section) between UDM events and a calculated table stage. This pattern lets you perform statistical anomaly detection, as shown in the following Mean Absolute Deviation (MAD) calculation:  `median` stage: Calculates the median bytes sent for each source host and target IP pair.  `$median.host`: singular, string `$median.target`: singular, string `$median.median`: singular, float  `absolute_deviations` stage: Joins each UDM event with the corresponding row from the median stage. This lets you calculate the absolute deviation of the bytes sent for every individual event relative to its peer group.  `$absolute_deviations.host`: singular, string `$absolute_deviations.target`: singular, string `$absolute_deviations.absolute_deviation`: singular, float  Root stage: Calculates the mean of those absolute deviations across all UDM events to establish an anomaly threshold.
#### Example: Configure a matchless join
```
stage median {
  metadata.event_type = "NETWORK_CONNECTION"
  $host = principal.hostname
  $target = target.ip

  match:
    $host, $target

  outcome:
    $median = window.median(network.sent_bytes, true)
}

stage absolute_deviations {
  metadata.event_type = "NETWORK_CONNECTION"
  $join_host = principal.hostname
  $join_host = $median.host
  $join_target = target.ip[0]
  $join_target = $median.target

  outcome:
    $host = $join_host
    $target = $join_target
    $absolute_deviation = math.abs(network.sent_bytes - $median.median)
}

$host = $absolute_deviations.host
$target = $absolute_deviations.target

match:
  $host, $target

outcome:
  $mean_absolute_deviation = avg($absolute_deviations.absolute_deviation)

```
### Example: Matchless join between windowed stage and table stage
The following example illustrates how to configure a matchless join between a windowed stage and a table stage in a multi-stage query.  `hourly_stats` stage calculates the total bytes sent for each source and target host pair and hour bucket. `hourly_stats` stage outputs the following stage fields corresponding with columns in output rows:  `$hourly_stats.source_host`: singular, string `$hourly_stats.dst_host`: singular, string `$hourly_stats.total_bytes_sent`: singular, float `$hourly_stats.window_start`: singular, integer `$hourly_stats.window_end`: singular, integer  `agg_stats` stage calculates the average and standard deviation of bytes per hour for each source and target host pair.
`agg_stats` outputs the following stage fields corresponding with columns in output rows:  `$agg_stats.source_host`: singular, string `$agg_stats.dst_host`: singular, string `$agg_stats.avg_bytes_sent`: singular, float `$agg_stats.stddev_bytes_sent`: singular, float
Root stage joins each row from `hourly_stats` with the row from `agg_stats` for the same source and target host pair. For each source and target host pair, it calculates the z-score using the total bytes sent for that host pair bucket and the aggregate statistics.
```
stage hourly_stats {
 $source_host = principal.hostname
 $dst_host = target.hostname
 principal.hostname != ""
 target.hostname != ""
 match:
   $source_host, $dst_host by hour
 outcome:
   $total_bytes_sent = sum(network.sent_bytes)
}

stage agg_stats {
  $source_host = $hourly_stats.source_host
  $dst_host = $hourly_stats.dst_host
  match:
    $source_host, $dst_host
  outcome:
   $avg_bytes_sent = avg($hourly_stats.total_bytes_sent)
   $stddev_bytes_sent = stddev($hourly_stats.total_bytes_sent)
}

$source_host = $agg_stats.source_host
$source_host = $hourly_stats.source_host

$dst_host = $agg_stats.dst_host
$dst_host = $hourly_stats.dst_host

outcome:
  $hour_bucket = timestamp.get_timestamp($hourly_stats.window_start)
  $z_score = ($hourly_stats.total_bytes_sent - $agg_stats.avg_bytes_sent)/$agg_stats.stddev_bytes_sent

```
## Cross joins in multi-stage queries
When using Google SecOps Search or Dashboards, cross joins in multi-stage queries let you compare individual UDM event data against aggregated statistics calculated in other YARA-L stages.
In YARA-L, the `cross join` keyword works with a stage that returns only one row.
When a cross join is used between a stage with a limit of 1 and another dataset (for example, UDM events), the single row output from the stage is appended to each row of the other dataset. This enriches the event data with the overall statistics.
### Example: Find unusual login activity
The following example identifies the users who sign in more frequently than normal. It calculates this by comparing each user's login count (using the `user_login_counts` stage) against the average login count across all users (using the `total_users` stage). Users who login an unusual number of times can be sorted in the search results.
You then use the cross join keyword to link the results from the `total_users` stage to the results from the `user_login_counts` stage.
```
stage user_login_counts {
    $user = principal.user.userid
    metadata.event_type = "USER_LOGIN"
    security_result.action = "ALLOW"

    match:
        $user

    outcome:
        $login_count = count(metadata.id)
}

stage total_users {
    outcome:
        $count = count($user_login_counts.user)
    limit:
        1
}

cross join $total_users, $user_login_counts

$login_count = $user_login_counts.login_count
$user = $user_login_counts.user
$tot_users = $total_users.count

// all users who logged in the same number of times are grouped together.
match:
    $login_count
outcome:
    $num_users = count($user)
    $frequency_percent = (count($user) / max($tot_users) ) * 100

```
## Limitations
Multi-stage queries have the following functional and structural constraints:
### Structural requirements
You must follow these structural requirements when you build your queries:  Root stage: Only one root stage is allowed per query. Named stages: A maximum of four named stages are supported. Stage referencing: A stage can only reference stages defined logically before it in the same query. Cross joins: A cross join can only reference a stage that returns a single row. You must include a limit (`1`) in the referenced stage to satisfy this requirement. This is beneficial because it lets you append a single global statistic (like a maximum or average) to every individual event row for comparison. Joins: A maximum of four non-data-table joins are allowed across all stages. Outcome requirement: Each named stage (excluding the root stage) must include either a `match` section or an `outcome` section where the `outcome` section doesn't require aggregation.
### Window and compatibility limits
The following restrictions apply to how you use windows and where you run queries:  Feature support: Multi-stage queries work in Search and Dashboards, but the feature is unsupported in Rules. Window types: Avoid mixing different window types within a single query. Window dependency: A stage using a hop or sliding window can't depend on another stage that also uses a hop or sliding window. Tumbling window size: While tumbling windows in different stages can vary in size, the difference in size must be less than 720x.
#### Example: Stage aggregation difference (invalid)
The following configuration is invalid because a month contains 44,640 minutes (44,640 / 1 > 720):
Stage: `monthly_stats { ... match: by month }`
Root: `match: by minute`
#### Example: Stage aggregation difference (valid)
To fix this, make sure the ratio between stages is smaller. For example, aggregate hourly data into a daily report:
Stage: `daily_stats { ... match: by day }`
Root: `match: by hour`
Because 24 (hours in a day) is less than 720, the system can efficiently map the stage data to the root stage.
### Stage and query limitations
Each individual stage within a multi-stage query has specific constraints. Most limitations that apply to a single-stage query also apply to each individual stage:  Output requirement: Every stage must output at least one match or outcome variable (stage field).
Query time range:  Standard queries: Maximum is 30 days. Multi-stage queries with matchless joins: Maximum is restricted to 14 days.
Window size limits: The maximum window size (hop, sliding, or tumbling) depends on whether your query includes a join:
With joins: Maximum window size for any type (hop, sliding, or tumbling) is 2 days. For details, see search joins limitations.
Without joins (single event):
Hop and sliding windows: Maximum is 2 days.
Tumbling windows: Maximum increases to 30 days.
Maximum outcome variables:  20 by default 50 for customers opted-in for the larger limit Array limits: A maximum of 10,000 elements are allowed in an array-valued outcome variable.
Event constraints per query:  Maximum of two UDM events Maximum of one ECG event Maximum of two data tables   Note: You can't join data table, UDM, and ECG events together in a single query.
### Service and performance limits
Multi-stage queries are subject to the same limitations as statistics queries:  Statistics queries: 120 QPH (API and UI). Search views: 100 views per minute. API support: The Google SecOps system and the `EventService.UDMSearch` API support multi-stage joins, but the `SearchService.UDMSearch` API does not. The system also lets you run multi-stage queries without joins.
### Event and global limitations
You must stay within these event and platform-wide boundaries:
#### Maximum events
Multi-stage queries strictly limit the number of events they can process simultaneously:  UDM events: A maximum of 2 UDM events are allowed. Entity Context Graph (ECG) events: A maximum of one ECG event is allowed.
#### Global query limitations
These platform-wide constraints control how far back and how much data a multi-stage query returns:  Query time range: The maximum time range for a standard query is 30 days. Total result set: The maximum total result set size is 10,000 results.