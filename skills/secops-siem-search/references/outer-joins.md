# Source: https://docs.cloud.google.com/chronicle/docs/investigation/outer-joins

# Correlate data using outer joins
Supported in:
Google SecOps   SIEM
Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms. If this feature isn't visible in your environment, see Manage preview features or contact your system administrator.
This document describes outer joins (left join and right join). Join operations are used to correlate and combine data from multiple sources based on common field values. By combining related security events and entities into a single, comprehensive view, you can provide effective threat detection and investigation.
Unlike standard (inner) joins, which require matching entries in both data sources, an outer join retrieves all records from one side of the join, even if there are no matching entries in the other. Unmatched fields from the other side are typically filled with `null`. This prevents you from losing data that doesn't have a match.
## How outer joins work
The concept of outer joins in YARA-L 2.0 is identical to standard SQL outer joins:
The left outer join preserves all records from the left side of the join.
The right outer join preserves all records from the right side of the join.
Outer join syntax (left join and right join) is supported for all queries—both with and without a `match` condition. The fundamental behavior of an outer join is the same across search, dashboards, and detection rules, although the syntax differs according to context:
Search and dashboards: Use the explicit `left join` or `right join` keywords in the `events` section.
Detection rules: Define the join relationship using an equals sign (`=`) in the `events` section and specify an unbounded condition in the `condition` section (for example, `#data_table >= 0` for a left outer join or `#data_table = 0` for an anti-join exclusion).
## Understand the left outer join
A left outer join (or left join) preserves all records from the data source on the left (preserved) side of the join, whether you use the `left join` keyword in Search or an unbounded condition (`#data_table >= 0`) in a detection rule.
If a record from the left side has no match in the right event or data table, the fields from the right side are returned as `null`.
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
## Left joins in detection rules
In detection rules, you don't use the `left join` keyword in the `events` section. Instead, you link a UDM event to a data table or secondary event in the `events` section using equality (`=`), and control the join behavior in the `condition` section:    Join type `events` section `condition` section Behavior on unmatched events     Inner join `$key = %data_table.key` `$e and #data_table > 0` Unmatched events are dropped from the detection stream.   Left outer join (enrichment) `$key = %data_table.key` `$e and #data_table >= 0` All events in `$e` are preserved; unmatched data table fields are `null`.   Anti-join (exclusion) `$key = %data_table.key` `$e and #data_table = 0` Triggers an alert only when the event key doesn't exist in the data table.
### Event-to-data-table left join example in a rule
The following example uses a data table named `corporate_asset_directory` to enrich events with asset criticality and geographic metadata without dropping events from unmanaged hosts.
#### Define the data table
The `corporate_asset_directory` data table contains the following rows, using `hostname` as the key column:    `hostname` (key) `country_code` `country_name` `asset_tier` `owner_dept` `risk_score`     `ES01-W10` `ES` `Spain` `TIER_3_WORKSTATION` `Finance` `20`   `CH02-SRV` `CH` `Switzerland` `TIER_1_CRITICAL` `Engineering` `80`   `US03-LAP` `US` `United States` `TIER_2_PRODUCTION` `Executive` `50`
#### Compare inner join and left outer join conditions
Inner join (`#corporate_asset_directory > 0`): Requiring the data table count to be greater than `0` performs an inner join. If an event originates from an unmanaged host that isn't listed in `corporate_asset_directory` (for example, `unmanaged-byod-09`), the event is filtered out and no detection is generated:
```
rule inner_join_drops_unmatched_events {
  meta:
    author = "Google SecOps"
    description = "Inner join example: drops events whose hostname is not in the data table."

  events:
    $e.principal.hostname != ""
    $hostname = $e.principal.hostname

    // Direct inner join against data table
    $hostname = %corporate_asset_directory.hostname

  match:
    $hostname over 1h

  outcome:
    $country = array_distinct(%corporate_asset_directory.country_code)
    $asset_tier = array_distinct(%corporate_asset_directory.asset_tier)
    $risk_score = max(%corporate_asset_directory.risk_score)

  condition:
    $e and #corporate_asset_directory > 0
}

```
Left outer join (`#corporate_asset_directory >= 0`): Using the unbounded condition `#corporate_asset_directory >= 0` performs a left outer join. All events in `$e` are preserved even when the hostname doesn't match a row in `corporate_asset_directory`.
When an event doesn't match a data table row, references to `%corporate_asset_directory.column` evaluate to `null`. In the `outcome` section, use `strings.coalesce` for string columns and conditional `if` expressions for numeric columns to assign default fallback values:
```
rule left_outer_join_enrichment {
  meta:
    author = "Google SecOps"
    description = "Left outer join using #dt >= 0: preserves all events and populates enrichment fields."

  events:
    $e.principal.hostname != ""
    $hostname = $e.principal.hostname

    // Outer join equality binding
    $hostname = %corporate_asset_directory.hostname

  match:
    $hostname over 1h

  outcome:
    $country = array_distinct(strings.coalesce(%corporate_asset_directory.country_code, "UNKNOWN"))
    $asset_tier = array_distinct(strings.coalesce(%corporate_asset_directory.asset_tier, "UNMANAGED"))
    $risk_score = max(if(%corporate_asset_directory.risk_score > 0, %corporate_asset_directory.risk_score, 0))

  condition:
    $e and #corporate_asset_directory >= 0
}

```
Rule join result
The following table compares the resulting outcome values for matched and unmatched hosts when using `#corporate_asset_directory >= 0`:    Principal hostname (`$hostname`) Data table match status `$country` `$asset_tier` `$risk_score`     `CH02-SRV` Match found `["CH"]` `["TIER_1_CRITICAL"]` `80`   `ES01-W10` Match found `["ES"]` `["TIER_3_WORKSTATION"]` `20`   `unmanaged-byod-09` No match (`null` replaced by defaults) `["UNKNOWN"]` `["UNMANAGED"]` `0`
### Left anti-join (exclusion) examples in rules
You can use a left outer join with a zero-count condition (`#data_table = 0`) to perform a left anti-join. This pattern suppresses detections when an event matches an exclusion data table and triggers an alert only when no match exists.
Single-column exclusion (`#authorized_scanners_exclusion = 0`): The following rule joins `$e.principal.hostname` with an `authorized_scanners_exclusion` data table and triggers only when the host is not present in the table:
```
rule anti_join_scanner_exclusion {
  meta:
    author = "Google SecOps"
    description = "Anti-join exclusion using #dt = 0: triggers only if the host is not in the authorized scanners table."

  events:
    $e.principal.hostname != ""
    $hostname = $e.principal.hostname

    // Bind join key to data table
    $hostname = %authorized_scanners_exclusion.hostname

  match:
    $hostname over 1h

  outcome:
    $total_sent_bytes = sum($e.network.sent_bytes)

  condition:
    $e and #authorized_scanners_exclusion = 0
}

```
Alternatively, you can count the matched data table rows in the `outcome` section (`$scanner_match_count = count(%authorized_scanners_exclusion.hostname)`) and evaluate `$e and $scanner_match_count = 0` in the `condition` section:
```
rule anti_join_outcome_count {
  meta:
    author = "Google SecOps"
    description = "Anti-join via outcome variable count check: triggers when scanner match count is zero."

  events:
    $e.principal.hostname != ""
    $hostname = $e.principal.hostname

    $hostname = %authorized_scanners_exclusion.hostname

  match:
    $hostname over 1h

  outcome:
    $total_sent_bytes = sum($e.network.sent_bytes)
    $scanner_match_count = count(%authorized_scanners_exclusion.hostname)

  condition:
    $e and $scanner_match_count = 0
}

```
Multi-column row-tuple exclusion (`#multi_column_admin_exceptions = 0`): To exclude events only when a specific combination of multiple fields matches the same row in an exception data table, bind each event field to its corresponding column in the `events` section and specify `#data_table = 0` in the `condition` section:
```
rule multi_column_tuple_exclusion {
  meta:
    author = "Google SecOps"
    description = "Multi-column row-tuple anti-join: excludes activity matching composite (origin_ip, target_ip, username, action) rows."

  events:
    // Bind event fields to match variables
    $e.principal.ip = $src_ip
    $e.target.ip = $dst_ip
    $e.principal.user.userid = $user
    $e.metadata.product_event_type = $action

    // Multi-column equality against the same data table row
    $src_ip = %multi_column_admin_exceptions.origin_ip
    $dst_ip = %multi_column_admin_exceptions.target_ip
    $user = %multi_column_admin_exceptions.username
    $action = %multi_column_admin_exceptions.action

  match:
    $src_ip, $dst_ip, $user, $action over 5m

  outcome:
    $event_count = count($e.metadata.id)

  condition:
    $e and #multi_column_admin_exceptions = 0
}

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
The explicit `left join` and `right join` keywords in the `events` section aren't supported in detection rules and are supported only in YARA-L searches and dashboards. To perform a left outer join or anti-join in a detection rule, use an unbounded condition such as `#data_table >= 0` or `#data_table = 0` in the `condition` section. For details, see Left joins in detection rules.
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