# Source: https://docs.cloud.google.com/chronicle/docs/investigation/outer-joins

# Correlate data with outer joins
Supported in:
Google secops   SIEM
Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms.
This document describes outer joins (left join and right join). Join operations are used to correlate and combine data from multiple sources based on common field values. By combining related security events and entities into a single, comprehensive view, you can provide effective threat detection and investigation.
Unlike standard (inner) joins, which require matching entries in both data sources, an outer join retrieves all records from one side of the join, even if there are no matching entries in the other. Unmatched fields from the other side are typically filled with `null`. This prevents you from losing data that doesn't have a match.
## How outer joins work
The concept of outer joins in YARA-L 2.0 is identical to standard SQL outer joins:
The left outer join preserves all records from the left side of the join.
The right outer join preserves all records from the right side of the join.
Outer join syntax (left join and right join) is supported for all queries–both with and without a `match` condition.
## Understand the left outer join
A left outer join (or left join) preserves all records from the data source on the left side of the `left join` keyword.
If a record from the left side has no match in the right event, the fields from the right event are returned as `null`.
Placeholder implication: Any placeholder variable used in the `match` section must reference a field from the left event to ensure accurate data aggregation across the full result set.
## Event-to-event left join example
The following example demonstrates a left outer join to correlate user login events with subsequent network connection events occurring on the same host. The left join ensures that all `USER_LOGIN` events are preserved in the result set. If a matching `NETWORK_CONNECTION` event (`$e2`) is found, its data is joined. If no match is found, the fields for `$e2` are `null`.
```

$e1.metadata.event_type = "USER_LOGIN"
$e2.metadata.event_type = "NETWORK_CONNECTION"
left join $e1.principal.hostname = $e2.principal.hostname

```
### Define the left event
The following query example defines the left side of the join (`$e1`), which is the event set that is preserved in the final result:
```
$e1.metadata.event_type = "USER_LOGIN"

```
The following table represents the query result, identifying the initial set of user login events:   Event type  Principal hostname  IP address    `USER_LOGIN`  `workstation-01`  `192.168.1.101`    `USER_LOGIN`  `laptop-hr-02`  `192.168.1.102`    `USER_LOGIN`  `server-db-03`  `10.0.0.50`    `USER_LOGIN`  `kiosk-4`  `192.168.1.104`
### Define the right event
The following query example defines the right side of the join (`$e2`), which is the event set that is matched against the left events:
```
$e2.metadata.event_type = "NETWORK_CONNECTION"

```
The following table represents the set of network connection events available for matching:   Event type  Principal hostname  IP address    `NETWORK_CONNECTION`  `workstation-01`  `192.168.1.101`    `NETWORK_CONNECTION`  `laptop-hr-02`  `192.168.1.101`    `NETWORK_CONNECTION`  `kiosk-4`  `203.0.113.3`
### Join the events
with a match section
The following example demonstrates a match query using a left outer join on the `principal.hostname` field:
```

  $e1.metadata.event_type = "USER_LOGIN"

  $e2.metadata.event_type = "NETWORK_CONNECTION"

  left join $e1.principal.hostname = $e2.principal.hostname

  $host = $e1.principal.hostname

  match:
    $host over 5m

```
The left outer join ensures that every `USER_LOGIN` event (`$e1`) is included in the final result set.
The placeholder $host is assigned the value from `$e1.principal.hostname`. The left outer join ensures the presence of event `$e1`, making sure that the $host variable is always populated for aggregation.
The rule aggregates the results by the host for a 5-minute time window.
Join result
The resulting data shows the combination of the two events. All records from the left table (`$e1`) are retained, and fields from the right table (`$e2`) are set to `null` when no matching hostname is found (for example, for `server-db-03`).   Event type (`$e1`)  Principal hostname (`$host`)  IP address (`$e1`)  Event type (`$e2`)  IP address (`$e2`)  Match status    `USER_LOGIN`  `workstation-01`  `192.168.1.101`  `NETWORK_CONNECTION`  `192.168.1.101`  Match found    `USER_LOGIN`  `laptop-hr-02`  `192.168.1.102`  `NETWORK_CONNECTION`  `192.168.1.101`  Match found    `USER_LOGIN`  `server-db-03`  `10.0.0.50`  `null`  `null`  No match    `USER_LOGIN`  `kiosk-4`  `192.168.1.104`  `NETWORK_CONNECTION`  `203.0.113.3`  Match found
## Example left join queries
This section provides example left join queries.
### Joins with a match condition
Event-entity
```

$e1.metadata.event_type = "NETWORK_CONNECTION"
$g1.graph.metadata.entity_type = "ASSET"
left join $e1.principal.asset.hostname = $g1.graph.entity.asset.hostname
$host = $e1.principal.asset.hostname

match:
  $host over 5m

```
Event-datatable
```

$host = $e1.principal.hostname
left join $e1.principal.hostname = %all_dt_column_types.hostname

match:
  $host by 5m

```
### Joins without a match condition
Event-event
```

$e1.metadata.event_type = "USER_LOGIN"
$e1.principal.ip = "114.241.96.87"
$e2.metadata.event_type = "NETWORK_CONNECTION"
left join $e1.principal.hostname = $e2.principal.hostname

```
Event-entity
```

$e1.metadata.event_type = "NETWORK_CONNECTION"
$g1.graph.metadata.entity_type = "ASSET"
left join $e1.principal.asset.hostname = $g1.graph.entity.asset.hostname
$host = $e1.principal.asset.hostname

```
Event-datatable
```

$host = $e1.principal.hostname
left join $e1.principal.hostname = %all_dt_column_types.hostname

```
## Right outer join
A right outer join (or right join) preserves all records from the data source on the right side of the `right join` keyword.
If a record from the right event has no match in the left event, the fields from the left event are returned as `null`.
Placeholder implication: Any placeholder variable used in the `match` section must reference a field from the right event to ensure accurate data aggregation across the full result set.
## Event-to-Event right join example
The following example demonstrates a `right outer join` to correlate user login events with subsequent network connection events occurring on the same host. The `right join`ensures that all `NETWORK_CONNECTION` events are preserved in the result set. If a matching `USER_LOGIN` event is found, its data is joined. If no match is found, the fields for`$e1` are `null`.
```

$e1.metadata.event_type = "USER_LOGIN"

$e2.metadata.event_type = "NETWORK_CONNECTION"

right join $e1.principal.hostname = $e2.principal.hostname

```
### Define left event
The following query defines the left side of the join (`$e1`), which is the optional event set in the final result:
```

$e1.metadata.event_type = "USER_LOGIN"

```
The following table represents the result of the query, identifying the initial set of user login events:   Event type  Principal hostname  IP address    `USER_LOGIN`  `workstation-01`  `192.168.1.101`    `USER_LOGIN`  `laptop-hr-02`  `192.168.1.102`    `USER_LOGIN`  `server-db-03`  `10.0.0.50`
### Define right event
The following query defines the right side of the join (`$e2`), which is the event set that is preserved in the final result.
```

$e2.metadata.event_type = "NETWORK_CONNECTION"

```
The following table represents the set of network connection events available for matching.   Event type  Principal hostname  IP address    `NETWORK_CONNECTION`  `workstation-01`  `192.168.1.101`    `NETWORK_CONNECTION`  `laptop-hr-02`  `192.168.1.101`    `NETWORK_CONNECTION`  `vm-unauth-05`  `203.0.113.3`
### Join the events
The following example shows a match query with a right outer join on the `principal.hostname` field:
```

$e1.metadata.event_type = "USER_LOGIN"

$e2.metadata.event_type = "NETWORK_CONNECTION"

right join $e1.principal.hostname = $e2.principal.hostname

$host = $e1.principal.hostname

match:
  $host over 5m

```
The right outer join ensures that every `NETWORK_CONNECTION` event (`$e2`) is included in the final result set.
The placeholder `$host` is assigned the value from `$e2.principal.hostname`. The right outer join ensures the presence of event `$e2`, making sure the `$host` variable is always populated for aggregation.
The rule aggregates the results by the host for a 5-minute time window.
Join result
The resulting dataset shows the combination of the two events. All records from the right table (`$e2`) are retained, and fields from the left table (`$e1`) are set to null when no matching hostname is found (for example, `vm-unauth-05`).   Event type (`$e1`)  Principal hostname (`$e1`)  IP address (`$e1`)  Event type (`$e2`)  Principal hostname ($host)  IP address (`$e2`)  Match status    `USER_LOGIN`  `workstation-01`  `192.168.1.101`  `NETWORK_CONNECTION`  `workstation-01`  `192.168.1.101`  Match found    `USER_LOGIN`  `laptop-hr-02`  `192.168.1.102`  `NETWORK_CONNECTION`  `laptop-hr-02`  `192.168.1.101`  Match found    `null`  `null`  `null`  `NETWORK_CONNECTION`  `vm-unauth-05`  `203.0.113.4`  No match
## Example right join queries
This section provides example right join queries.
### Joins with a match condition
Event-event
```

$e1.metadata.event_type = "USER_LOGIN"

$e2.metadata.event_type = "NETWORK_CONNECTION"

right join $e1.principal.hostname = $e2.principal.hostname

$host = $e2.principal.hostname

match:
  $host over 5m

```
Entity-event
```

$e1.metadata.event_type = "NETWORK_CONNECTION"

$g1.graph.metadata.entity_type = "ASSET"

right join $g1.graph.entity.asset.hostname = $e1.principal.asset.hostname

$host = $e1.principal.asset.hostname

match:
  $host over 5m

```
Datatable-event
```

$host = $e1.principal.hostname

right join %all_dt_column_types.hostname = $e1.principal.hostname

match:
  $host by 5m

```
### Joins without a match condition
Event-event
```

$e1.metadata.event_type = "USER_LOGIN"

$e1.principal.ip = "114.241.96.87"

$e2.metadata.event_type = "NETWORK_CONNECTION"

right join $e1.principal.hostname = $e2.principal.hostname

```
Entity-event
```

$e1.metadata.event_type = "NETWORK_CONNECTION"

$g1.graph.metadata.entity_type = "ASSET"

right join $g1.graph.entity.asset.hostname = $e1.principal.asset.hostname

$host = $e1.principal.asset.hostname

```
Datatable-event
```

$host = $e1.principal.hostname

right join %all_dt_column_types.hostname = $e1.principal.hostname

```
## Limitations
Consider the following limitations when you create outer joins:
A full outer join (left join and right join together) is not supported.
The query time range for matchless joins is limited to a maximum of 14 days.
You cannot directly join two contextual sources (for example, an entity directly to a datatable).
The primary Unified Data Model (UDM) event must be the preserved side of the outer join. The query is invalid if the primary event is on the "nullable" side.
An event-entity join must be a left join. This correctly preserves the event (`$e1`).
An entity-event join must be a right join. This correctly preserves the event (`$e1`).
The following example is invalid because the UDM event (`$e1`) is on the left, but the right join preserves the right side (`$g1`), which violates the rule that the UDM event must be preserved:
```

// Invalid query
$e1.metadata.event_type = "NETWORK_CONNECTION"
$g1.graph.metadata.entity_type = "ASSET"
right join $e1.principal.asset.hostname = $g1.graph.entity.asset.hostname

```
## Best practices
To prevent slow performance and query timeouts in outer join queries, use specific and narrow filters.
For example, a broad query like the following:
```

$e1.metadata.event_type = "USER_LOGIN"
$e2.metadata.event_type = "NETWORK_CONNECTION"
right join $e1.principal.hostname = $e2.principal.hostname

```
Can be optimized by adding specific criteria follows:
```

$e1.metadata.event_type = "USER_LOGIN"
$e1.principal.ip = "121.121.121.121"
$e1.principal.user.userid = "alex"
$e2.metadata.event_type = "NETWORK_CONNECTION"
$e2.src.hostname = "altostrat.com"
$e1.principal.hostname = $e2.principal.hostname

```