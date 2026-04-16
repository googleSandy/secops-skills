# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/match-syntax

# Match section syntax
Supported in:    Google secops   SIEM
In YARA-L 2.0, the `match` section provides the mechanism for multi-event correlation. It defines the logic for grouping events into a single detection by linking common attributes, such as users, IP addresses, or file hashes, within a specific temporal boundary.
You use the `match` section for the following use cases:  Link two or more distinct events within a rule. Aggregate data in Search and Dashboards, such as counting failed login attempts over a specific timeframe.
## Define correlation criteria
Use it to define the criteria for this correlation by specifying the following:
Grouping fields (keys): Variables (like `$user` or `$ip`) that must have identical values across events (defined in the `events` section) to trigger a match.
Time constraint: The duration window in which grouped events must occur to satisfy the rule or aggregation. In Rules, this defines the detection window; in Search and Dashboards, this defines the aggregation or correlation window.
### Compare feature requirements
The following table details the comparisons for Rules to Search and Dashboards.    Feature Rules requirement Search and Dashboards support     Variable types Must use placeholders defined in `events` section. Supports both placeholders and direct UDM fields.   Time window Defines the detection boundary. Defines the aggregation or correlation bucket.   Syntax `over <number><m/h/d>` (for example, `10m`, `2h`, `1d`) `over <number><m/h/d>`   Limits Min: `1m` / Max: `48h` Min: `1m` / Max: `48h`
## Supported window types
YARA-L 2.0 uses different windowing behaviors to determine how time is sliced and how events are grouped. You can group event fields and placeholders in the `match` section by a specified time granularity using one of the following supported windows.
For details about YARA-L 2.0-supported window types, see YARA-L 2.0 windowing logic.
## Understand the temporal boundary
The `match` section partitions events into groups based on your grouping keys. The specified duration defines the temporal boundary for each group:  Inclusion: Only events within the window are passed to the `condition` evaluation for that specific match. Exclusion: Events outside the window are ignored for that specific match group, preventing unrelated events from triggering a false positive.
## Zero values in the `match` section
Google SecOps implicitly filters out zero values for all placeholders that are used in the `match` section (`""` for string, `0` for numbers, `false` for booleans, the value in position `0` for enumerated types).
### Example: Filter out zero values
The following example illustrates queries that filter out the zero values.
```
rule ZeroValuePlaceholderExample {

events:
  // Because $host is used in the match section, the query behaves
  // as if the following predicate was added to the events section:
  // $host != ""
  $host = $e.principal.hostname

  // Because $otherPlaceholder was not used in the match,
  // there is no implicit filtering of zero values for $otherPlaceholder.
  $otherPlaceholder = $e.principal.ip

match:
  $host over 5m

condition:
  $e
}
```
However, if a placeholder is assigned to a function, queries don't implicitly filter out the zero values of placeholders that are used in the `match` section.
To disable the implicit filtering of zero values, you can use the `allow_zero_values` option in the options section. The `allow_zero_values` option is only available in Rules.
### Example: Allow zero values
The following example illustrates queries that don't implicitly filter out the zero values of placeholders that are used in the `match` section:
```
rule AllowZeroValuesExample {

events:
  // Because allow_zero_values is set to true, there is no implicit filtering
  // of zero values for $host.
  $host = $e.principal.hostname

  // Because $otherPlaceholder was not used in the match,
  // there is no implicit filtering of zero values for $otherPlaceholder.
  $otherPlaceholder = $e.principal.ip

match:
  $host over 5m

condition:
  $e

options:
  allow_zero_values = true
}
```