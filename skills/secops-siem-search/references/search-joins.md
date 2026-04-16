# Source: https://docs.cloud.google.com/chronicle/docs/investigation/search-joins

# Use joins in Search
Supported in:
Google secops   SIEM
Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms.
Joins help correlate data from multiple sources to provide more context for an investigation. By linking related events, entities, and other data, you can investigate complex attack scenarios.
This document explains how to use the join operation in Google Security Operations. It also covers supported join types, use cases, and best practices.
## Create a join
Only statistics-based joins are supported. You must define them in the match section of a query with a correlation time window of up to 48 hours. You can create a join by either connecting fields directly (for example, `$e1.hostname = $e2.hostname`) or by using placeholder variables. When you define a join in the `match` section, you must use placeholder variables. Note: The match window is different from the search time range you select in the user interface. The search time range selects the historical block of data to analyze while the match window defines the specific timeframe for events to be correlated.
The following example queries joins two fields with an equals sign (`=`) and a shared placeholder variable:
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
This section describes the different types of joins that you can use.
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
## Limitations
The following limitations apply when using joins:
You can use a maximum of two UDM events per query.
You can use a maximum of one ECG event per query.
You can use a maximum of two Datatables per query.
You cannot join datatable, UDM, and ECG events together in a single query.
The maximum query time range is 90 days.
The maximum `match` time window is 48 hours.
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