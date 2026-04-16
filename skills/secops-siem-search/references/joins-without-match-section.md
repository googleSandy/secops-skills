# Source: https://docs.cloud.google.com/chronicle/docs/investigation/joins-without-match-section

# Implement joins without a match section
Supported in:
Google secops   SIEM
Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms.
This document explains the concept of join operations without a `match` section or data join within Google Security Operations Search.
You can use join operations to correlate and combine raw data from multiple sources based on common field values. By combining related security events and entities into a single, comprehensive view, you can provide a more effective threat detection and investigation.
Unlike statistical joins that require a `match` section to aggregate results, a data join retrieves the complete event or entity data and displays them without any aggregation.
## How data joins work
You can create a data join by correlating common fields across different event or entity blocks. You can do this by one of these methods:
Directly equate the fields (for example, `$e1.principal.hostname = $e2.principal.hostname`)
Assign both fields to the same placeholder variable (for example, `$host = $e1.principal.hostname` and `$host = $e2.principal.hostname`).
In both cases, Search implicitly joins the blocks where the values of those fields are identical.
## Supported data join types
You can use the following data join types in your Search queries:
Event-to-Event joins: Correlate data between two different Unified Data Model (UDM) event types.
Event-to-ECG joins: Enrich UDM event data with information from the Entity Context Graph (ECG).
## Event-to-Event joins
Event-to-Event joins are best for correlating fields between two distinct UDM event types. This is useful for finding sequences of events or actions that involve the same entities across different log sources or event types.
The following query example finds all network connections (`NETWORK_CONNECTION`) originating from a host where a user login (`USER_LOGIN`) also occurred:
```

  // Find user logins and assign the hostname to the $host placeholder

  $e1.metadata.event_type = "USER_LOGIN"

  $host = $e1.principal.hostname

  // Find network connections and join them where the hostname matches the
  $host placeholder

  $e2.metadata.event_type = "NETWORK_CONNECTION"

  $host = $e2.principal.hostname

```
### Limitations
A maximum of two events can be joined.
The query time range is limited to a maximum of 14 days.
The query limit is 120 queries per hour (QPH).
### Examples
The following query example finds all network connections (`NETWORK_CONNECTION`) originating from a host where a user login (`USER_LOGIN`) also occurred:
```

  // Find user logins and assign the hostname to the $host placeholder

  $e1.metadata.event_type = "USER_LOGIN"

  $host = $e1.principal.hostname

  // Find network connections and join them where the hostname matches the $host
  placeholder

  $e2.metadata.event_type = "NETWORK_CONNECTION"

  $host = $e2.principal.hostname

```
#### Join on user ID
```

  $e1.metadata.event_type = "USER_LOGIN"

  $e1.security_result.action = "ALLOW"

  $e1.principal.user.userid = $user

  $e2.metadata.event_type = "NETWORK_CONNECTION"

  $e2.principal.user.userid = $user

```
#### Join on IP address
```

  $e1.metadata.event_type = "USER_LOGIN"

  $e1.security_result.action = "ALLOW"

  $e1.principal.ip = $ip

  $e2.metadata.event_type = "NETWORK_CONNECTION"

  $e2.principal.ip = $ip

```
## Event-to-Entity Context Graph joins
Event-to-ECG joins are best for enriching UDM events with contextual data about the involved entities (such as assets, users) from the ECG. This join provides a more complete picture by combining real-time event data with historical and relational entity information.
### Limitations
The query time range is limited to a maximum of 14 days.
The query limit is 120 QPH.
A maximum of two UDM events can be joined in the query.
A maximum of one ECG event can be joined in the query.
Export to a datatable isn't supported for Event-to-ECG join queries.
ECG-to-ECG joins are not supported.
ECG-to-datatable joins are not supported.
### Examples
This query enriches network connection events with asset information from the ECG by joining on the hostname.
```

  // Find network connections and assign the hostname to the $host placeholder

  $e1.metadata.event_type = "NETWORK_CONNECTION"

  $host = $e1.principal.asset.hostname

  // Find asset entities in the graph and join where the hostname matches the
  $host placeholder

  $g1.graph.metadata.entity_type = "ASSET"

  $host = $g1.graph.entity.asset.hostname

```
#### Join on IP address with a specific log type
```

  $ip = $e1.principal.ip

  $ip = $g1.graph.entity.ip

  $e1.metadata.log_type = "WINDOWS_DEFENDER_ATP"

  $g1.graph.entity.ip = "10.19.6.24"

```
#### Join on hostname with a specific IP filter
```

  $e1.metadata.event_type = "FILE_CREATION"

  $host = $e1.principal.hostname

  $e1.principal.ip = "10.0.0.76"

  $g1.graph.metadata.entity_type = "ASSET"

  $host = $g1.graph.entity.hostname

```
## Best practices
To avoid slow performance and query timeouts, use specific and narrow filters within each block (`$e1`, `$e2`, `$g1`) in your join queries.
For example, a broad query like the following:
```
$e1.metadata.event_type = "USER_LOGIN"
$e2.metadata.event_type = "NETWORK_CONNECTION"
right join $e1.principal.hostname = $e2.principal.hostname

```
Can be optimized by adding specific criteria follows:
```

$e1.metadata.event_type = "USER_LOGIN"
$e1.principal.ip = "192.168.1.101"
$e1.principal.user.userid = "alex"
$e2.metadata.event_type = "NETWORK_CONNECTION"
$e2.src.hostname = "altostrat.com"
right join $e1.principal.hostname = $e2.principal.hostname

```
## Work with results
The results of a data join display in a Joins table, including the combined fields from both correlated events. This table differs from a statistics view, where it provides the complete event or entity data, and not an aggregated count.
After running a query, you can work with the results in the following ways:
Download as CSV: Export the complete result set to a CSV file for offline analysis.
Export to datatables: Save the results to a datatable within your instance for reference or further correlation (only for Event-to-Event joins).