# Source: https://docs.cloud.google.com/chronicle/docs/investigation/search-joins

# Apply joins in search and dashboards
Supported in:
Google secops   SIEM
Joins help correlate data from multiple sources to provide more context for an investigation. By linking related events, entities, and other data, you can investigate complex attack scenarios and visualize trends.
This document explains how to use the join operation in the Google SecOps Search field and dashboard panels. It covers the supported join types, use cases, and best practices.
## Core concepts of joins
You can create a join by connecting data sources using shared placeholder variables or explicit equality statements (for example, `$e1.hostname = $e2.hostname`). When you define a join in the `match` section of a statistics-based query, you must use placeholder variables.
The following examples demonstrate how to link data sources using two fields with an equals sign (`=`) and a shared placeholder variable.
Example 1: Implicit join using placeholder variables
```
events:
  // Assign a value from the first event to the placeholder variable $user
  $user = $e1.principal.user.userid

  // The second assignment creates an implicit join, linking $e2 to $e1
  // where the user ID is the same.
  $user = $e2.principal.user.userid

match:
  $user over 1h

condition:
  $e1 and $e2

```
Example 2: Explicit join using equality and placeholders
```
$e1.principal.ip = $ip
$e1.metadata.event_type = "USER_LOGIN"
$e1.principal.hostname = $host

$e2.target.ip = $ip
$e2.principal.hostname = "altostrat"
$e2.target.hostname = $host

match:
  $ip, $host over 5m

```
## Joins in search
The examples in this section demonstrate syntax used in Search.
Queries in Search are case-insensitive by default.
### Event-event join
An event-event join connects two different Universal Data Model (UDM) events. The following example query links a `USER_LOGIN` event with another event to find the hostname (`altostrat`) that the user interacted with, based on a common IP address:
```
$e1.principal.ip = $ip
$e1.metadata.event_type = "USER_LOGIN"

$e2.target.ip = $ip
$e2.principal.hostname = "altostrat"

match:
  $ip over 5m

```
### Event-ECG join
An Event-ECG join connects a UDM event with an entity from the Entity Context Graph (ECG). The following example query finds a `NETWORK_CONNECTION` event and an `ASSET` from the entity graph that share the same hostname within a 1-hour window:
```
events:
  $e1.metadata.event_type = "NETWORK_CONNECTION"
  $g1.graph.metadata.entity_type = "ASSET"
  $e1.principal.asset.hostname = $g1.graph.entity.asset.hostname
  $x = $g1.graph.entity.asset.hostname

match:
  $x over 1h

condition:
  $e1 and $g1

```
### Datatable-event join
A datatable-event join connects UDM events with entries in a custom datatable. This is useful for checking live event data against a user-defined list, such as known malicious IP addresses or threat actors. The following example query joins `NETWORK_CONNECTION` events with a datatable to find connections involving specific IP addresses from that list:
```
$ip = %DATATABLE_NAME.COLUMN_NAME
$ip = $e1.principal.ip
$e1.metadata.event_type = "NETWORK_CONNECTION"

match:
  $ip over 1h

```
#### Use the IN clause with data tables
You can also use the `in` clause to check if a field value exists in a Data Table column. This syntax is supported across all data sources (for example, `ioc.type in %abc.type`) and provides a convenient way to filter events based on reference lists without defining explicit placeholder variables for the join.
## Common use cases
This section lists some common ways to use joins.
### Detect credential theft and use
Goal: Find instances where a user logs in successfully, and then quickly deletes a critical system file. This could suggest an account takeover or malicious insider activity.
Join type: Event-Event join
Description: This query connects two distinct events that aren't suspicious on their own, but become highly suspicious when they happen together. It first looks for a `USER_LOGIN` event, then a `FILE_DELETION` event. These are joined by the common `user.userid` with a short time window.
Credential theft detection query
```
// Event 1: A user successfully logs in
$e1.metadata.event_type = "USER_LOGIN"
$e1.security_result.action = "ALLOW"
$e1.principal.user.userid = $user

// Event 2: The same user deletes a critical file
$e2.metadata.event_type = "FILE_DELETION"
$e2.target.file.full_path = /etc\/passwd|C:\\Windows\\System32\\/
$e2.principal.user.userid = $user

match:
  $user over 10m

condition:
  $e1 and $e2

```
### Identify risky connections from critical assets
Goal: Enrich live network data with asset information to find outbound connections from servers that shouldn't communicate with external, low-prevalence domains (for example, a production database server).
Join type: Event-ECG join
Description: A single network connection to a rare domain might not be a high priority. However, this query increases the importance of that event by joining it with the Entity Context Graph (ECG). It specifically looks for `NETWORK_CONNECTION` events that come from assets labeled as "Critical Database Server" in the entity graph.
Risky connections query
```
events:
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.target.domain.prevalence.day_count <= 5

  $asset.graph.metadata.entity_type = "ASSET"
  $asset.graph.entity.asset.labels.value = "Critical Database Server"

  $e.principal.asset.hostname = $asset.graph.entity.asset.hostname
  $host = $e.principal.asset.hostname

match:
  $host over 1h

condition:
  $e and $asset

```
### Hunt for threat actor IOCs
Goal: Actively search for Indicators of Compromise (IoCs) by checking all live DNS queries against a list of domains known to be used by a specific threat actor.
Join type: Datatable-Event join
Description: Your threat intelligence team maintains a datatable called `ThreatActor_Domains` that lists malicious domains. This query joins all real-time `NETWORK_DNS_QUERY` events with this datatable. It immediately shows any instance where a host in your network tries to resolve a domain from your threat intelligence list.
Threat actor IOC hunt query
```
// Datatable: Get the list of malicious domains
$domain = %DATATABLE_NAME.COLUMN_NAME

// Event: A DNS query is made
$e.metadata.event_type = "NETWORK_DNS"
$e.network.dns.questions.name = $domain

match:
  $domain over 5m

condition:
  $e

```
## Joins in dashboards
Dashboards support a wider range of data sources and longer correlation windows than in Search. Unlike standard SQL queries, YARA-L 2.0 does not use explicit `JOIN` statements; instead, it connects data sources by correlating shared placeholder variables or using multistage queries.
### Case sensitivity
Dashboard queries are case-sensitive. To perform a case-insensitive join or search in a dashboard, use the `nocase` modifier.
### Supported data sources
In dashboards, you can join data from supported join combinations of data sources. (Not all combinations of data sources can be joined together in a single query.)
Every data reference in a multi-source dashboard query must include its YARA-L prefix qualifier (for example, `$u1`), not just the joined fields. This lets the system correctly identify field ownership across overlapping data sources.
#### Supported join combinations
Joins let you correlate UDM events, entity context, and data tables in built-in dashboards. To maintain system performance, review the supported combinations and technical limits in this section before building your queries.  UDM event to UDM event (multi-event) UDM event to entity context UDM event to datatable
Case to case history: This combination is strictly limited to exactly one `case` source and one `case_history` source. You cannot include any other data sources in this join. Note: To correlate SOAR case data (`case` or `case_history`) with SIEM UDM events, entity context, or datatables, consider exporting your datasets to BigQuery first. Once your data is exported, you can use standard SQL queries in BigQuery or build cross-source visualizations in business intelligence tools. For setup instructions, see Export to a self-managed BigQuery project.
For information about limits and guardrails, see Technical limits and constraints.
### Example: Join case and case_history
You can correlate case metadata with its historical activity by joining on the unique Case ID.
The following example joins `case` and `case_history` data sources to count the total number of historical actions for each high-priority case.
```
  // 1. Establish the Join using a shared placeholder variable ($case_id)
  $h.case_history.case_response_platform_info.case_id = $case_id
  $c.case.response_platform_info.response_platform_id = $case_id

  // 2. Apply Filters
  $c.case.priority = "PRIORITY_HIGH"

  // 3. Group the correlated data by the Case ID
  match:
    $case_id

  // 4. Calculate the selected metrics to display on the dashboard
  outcome:
    $case_name = array_distinct($c.case.display_name)
    $total_historical_actions = count($h.case_history.case_activity)

```
### Advanced use case: Computing MTTR
For more complex metrics like Mean Time to Resolve (MTTR) or Mean Time to Close (MTTC), you can use a multistage query. This lets you calculate the duration for each individual case in the first stage, and then average those durations globally in the final outcome block.
The following query computes the average time to close cases (in minutes) across all cases in the "Default Environment".
```
stage stage1 {
  // 1. Establish the Join
  $h.case_history.case_response_platform_info.case_id = $case_id
  $c.case.response_platform_info.response_platform_id = $case_id

  // 2. Filter by specific environment
  $c.case.environment = "Default Environment"

  // 3. Group by Case ID to process per case
  match:
    $case_id

  // 4. Calculate the Time to Close (TTC) for each case individually
  outcome:
    $case_close_time = max(if($h.case_history.case_activity = "CLOSE_CASE", $h.case_history.event_time.seconds, 0))
    $status = array_distinct($h.case_history.case_activity)

    // Subtract the very first event time (creation) from the close time
    $TTC = $case_close_time - min($h.case_history.event_time.seconds)

  // 5. Filter to ensure the case has a complete lifecycle
  condition:
    arrays.contains($status, "CREATE_CASE") and
    arrays.contains($status, "CLOSE_CASE")
}

// 6. Global Aggregation: Calculate the Mean (Average) across all processed cases
outcome:
  $case_count = count($stage1.case_id)
  $MTTC = (math.round(avg($stage1.TTC) / 60))

```
## Best practices
To optimize the performance of your join queries and make sure they process efficiently, follow these best practices for filtering events and managing search scope.
### Use specific filters to reduce the number of events
Join queries can be resource-intensive because they combine many results.
Broad, general filters can cause queries to fail, sometimes after a long delay, for example:
`target.ip != ""`
`metadata.event_type = "NETWORK_CONNECTION"` (if this event type is very common in your environment)
We recommend combining general filters with more specific ones to reduce the total number of events that the query needs to process. A broad filter like `target.ip != ""` should be paired with more specific filters to improve the performance of the query, for example:
```
$e1.metadata.log_type = $log
$e1.metadata.event_type = "USER_LOGIN"
$e1.target.ip != ""

$e2.metadata.log_type = $log
$e2.principal.ip = "10.0.0.76"
$e2.target.hostname != "altostrat"

match:
$log over 5m

```
If your query is still slow, you can also reduce the query's overall time range (for example, from 30 days to one week).
For more information, see YARA-L best practices.
## Technical limits and constraints
The following limitations and limits apply when using joins in Search and dashboards.
### Match window and query limits
The match window defines the specific timeframe for events to be correlated. This is different from the Search time range you select in the user interface.
#### Limits in search
Search is optimized for live or rapid investigations over shorter windows.    Query limit Usage     Up to 48 hours (some queries may support longer windows). Correlating events in rapid investigations.
#### Limits in dashboards
Dashboards support longer-term historical analysis.    Join type Query limit Usage     UDM-to-UDM and UDM-to-Entity 31 days High-volume telemetry queries.   Case-to-CaseHistory 90 days Lifecycle tracking queries.   Other supported configurations Up to 365 days Fallback for non-UDM or metric-based sources (for example, ingestion metrics).
### Data source and table limits
The maximum number of data sources and tables you can join in a single query depends on whether you are using Search or dashboards.
#### Search constraints
You can use a maximum of two UDM events per query. You can use a maximum of one ECG event per query. You can use a maximum of two Datatables per query. You cannot join a datatable directly to an entity context table; you must use a UDM event as an intermediary bridge (for example, correlate `$event.target.hostname` with both `$datatable.hostname` and `$asset.graph.entity.asset.hostname`).
#### Dashboard constraints
Join type Maximum event tables (UDM or datatable) Maximum entity tables     Multi-event (UDM to UDM) 2 N/A   UDM to entity 2 1   UDM to datatable 2 N/A   Multistage queries 2 1
### Performance and guardrails
The system monitors complex join queries for excessive resource consumption. To protect overall environment performance, the system might automatically pause or quarantine queries that exceed resource safety thresholds.
If a query fails or returns errors indicating that it exceeded resource limits, try the following optimizations:  Narrow the query time window. Add more specific filters to reduce the dataset size before the join occurs. Simplify your aggregations.
### API and query type constraints
Joins are supported in the user interface and the `EventService.UDMSearch` API, but not in the `SearchService.UDMSearch` API.