# Source: https://docs.cloud.google.com/chronicle/docs/investigation/search-joins

# Use joins in search and dashboards
Supported in:
Google secops   SIEM
Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms.
Joins help correlate data from multiple sources to provide more context for an investigation. By linking related events, entities, and other data, you can investigate complex attack scenarios and visualize trends.
This document explains how to use the join operation in Google Security Operations search and dashboards. It also covers supported join types, use cases, and best practices.
## Create a join
Only statistics-based joins are supported. You must define them in the `match` section of a query.
The correlation time window (match window) depends on whether you are using search or dashboards:  Search: Up to 48 hours. Dashboards: Up to 365 days (for most data sources).
You can create a join by either connecting fields directly (for example, `$e1.hostname = $e2.hostname`) or by using placeholder variables. When you define a join in the `match` section, you must use placeholder variables. Note: The match window is different from the search time range you select in the user interface. The search time range selects the historical block of data to analyze while the match window defines the specific timeframe for events to be correlated.
The following example queries join two fields with an equals sign (`=`) and a shared placeholder variable:
Example 1:
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
Example 2:
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
## Supported join types
This section describes the different types of joins that you can use. The examples in this section demonstrate syntax used in search. For information about joins in dashboards, see Joins in dashboards.
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
## Best practices
Join queries can be resource-intensive because they combine many results. Broad, general filters can cause queries to fail, sometimes after a long delay, for example:
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
## Joins in dashboards
Dashboards support a wider range of data sources and longer correlation windows than search.
### Supported data sources
In dashboards, you can join data from the following sources using their respective YARA-L prefixes:    Prefix Data Source     `case` Cases and alerts   `case_history` Activity trends across the case lifecycle   `detection` History of rule detections and analyst feedback   `ingestion` Log volume and ingestion health metrics   `ioc` IoC (Indicator of Compromise) matches   `playbook` Automated response and playbook execution metrics   `ruleset` / `rules` Metadata about active rule sets   `graph` Entity Graph data (ECG)   `events` UDM events
### Case sensitivity
Unlike search, which is case-insensitive by default, dashboards are case-sensitive. To perform a case-insensitive join or search in a dashboard, use the `nocase` modifier.
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
## Limitations
The following limitations apply when using joins:
You can use a maximum of two UDM events per query in search.
You can use a maximum of one ECG event per query in search.
You can use a maximum of two Datatables per query.
You cannot join datatable, UDM, and ECG events together in a single query.
The maximum query time range is 90 days.
The maximum `match` time window is 48 hours for search and 365 days for dashboards.
Joins are supported in the user interface and the `EventService.UDMSearch` API, but not in the `SearchService.UDMSearch` API.
## Common use cases
This section lists some common ways to use joins.
### Detect credential theft and use
Goal: Find instances where a user logs in successfully, and then quickly deletes a critical system file. This could suggest an account takeover or malicious insider activity.
Join type: Event-Event join
Description: This query connects two distinct events that aren't suspicious on their own, but become highly suspicious when they happen together. It first looks for a `USER_LOGIN` event, then a `FILE_DELETION` event. These are joined by the common `user.userid` with a short time window.
Sample query:
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
Sample query:
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
Sample query:
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