# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples

# YARA-L 2.0 query reference library
Supported in:    Google secops   SIEM
This document shows queries written in YARA-L 2.0. Each example demonstrates how to correlate events within the query rule language to identify security threats, monitor entity behavior, and enrich detections with business logic.
Use the examples as the building blocks of YARA-L 2.0, including single-event detection, regular expression matching, and network range filtering. These examples are organized into functional categories to help you progress from basic logic to advanced multi-event correlation and composite detections.
## Foundational syntax and basic
The examples in this section demonstrate how to effectively correlate UDM events and structure queries within the rule language.    Topic Examples     Single-event query  Initial user login search; 5-minute login detection    Querying and tuning Exclusion-based process detection   Network range and logic Single event matching (IP range)   Regular expressions in queries  Email filtering; Hostname regex; Raw log search    Repeated fields with universal conditions Suspicious login IP validation
### Single-event query
Use case: Basic detection of a specific event type (for example, `USER_LOGIN`) without needing to correlate across a time window.
Key logic: Uses only the events and condition sections to identify a single occurrence. A single-event rule can be:  Any rule without a `match` section. Rule with a `match` section and a `condition` section only checking for the existence of one event (for example, `$e`, `#e > 0`, `#e >= 1`, `1 <= #e`, `0 < #e`).
#### Example: Initial user login search
### Rule

The following rule example searches for a user login (`USER_LOGIN`) event and returns the first one it encounters within the enterprise data stored within your Google SecOps account:
```
rule SingleEventRule {
meta:
  author = "noone@altostrat.com"

events:
  $e.metadata.event_type = "USER_LOGIN"

condition:
  $e
}

```
### Search

This unaggregated search example outputs individual events directly. Because this query doesn't require event correlation, event variables, such as `$e1`, are omitted.
`metadata.event_type = "USER_LOGIN"`
### Dashboard

Because this query logic focuses on surfacing specific, non-correlated events in their raw state, it doesn't use the `match` or `outcome` sections required for dashboard visualizations.
#### Example: Five-minute login detection
### Rule

The following example shows a single-event rule that uses the `match` section to find any user with at least one login event occurring within a 5-minute (`5m`) time window. It checks for the existence of a user login event.
```
rule SingleEventRule {
meta:
  author = "alice@example.com"
  description = "windowed single event example rule"

events:
  $e.metadata.event_type = "USER_LOGIN"
  $e.principal.user.userid = $user

match:
  $user over 5m

condition:
  #e > 0
}

```
### Search

This statistical search example aggregates activity into five-minute (`5m`) tumbling windows, with output of one row per user per window. Because the query focuses on volumetric counts per window, `event` variables and `condition` sections are omitted, because results inherently include one or more events. This version uses a tumbling window instead of a hop window to make sure the results render correctly within the platform.
```
metadata.event_type = "USER_LOGIN"
principal.user.userid = $user

match:
  $user by 5m

```
### Dashboard

The following example incorporates an `outcome` section to calculate the total event count per user, which helps plot the data as a statistical value over time. The query uses a tumbling window instead of a hop window to make sure the data points map to discrete, non-overlapping buckets, and provides a clearer visualization for dashboard trending.
```
metadata.event_type = "USER_LOGIN"
principal.user.userid = $user

match:
  $user by 5m

outcome:
  $event_count = count(metadata.id)

```
### Querying and tuning
Use case: Detect Windows `svchost.exe`that launch from non-standard directories.
Key logic: Negation (`not`) combined with regular expression matching.
#### Example: Exclusion-based process detection
### Rule

The following rule checks for specific patterns in event data and creates a detection if it finds the patterns. This rule includes a variable `$e1` for tracking event type and `metadata.event_type` UDM field. The rule checks for specific occurrences of regular expression matches with `e1`. When the event `$e1` takes place, a detection is created. A `not` condition is included in the rule to exclude certain non-malicious paths. You can add `not` conditions to prevent false positives.
```
rule suspicious_unusual_location_svchost_execution
{
meta:
  author = "Google Cloud Security"
  description = "Windows 'svchost' executed from an unusual location"
  yara_version = "YL2.0"
  rule_version = "1.0"

events:
  $e1.metadata.event_type = "PROCESS_LAUNCH"
  re.regex($e1.principal.process.command_line, `\bsvchost(\.exe)?\b`) nocase
  not re.regex($e1.principal.process.command_line, `\\Windows\\System32\\`) nocase

condition:
  $e1
}

```
### Search

This example performs an unaggregated search to output individual events. Because this search doesn't require event correlation across multiple instances, event variables like `$e1` are unnecessary.
```
metadata.event_type = "PROCESS_LAUNCH"
re.regex(principal.process.command_line, `\bsvchost(\.exe)?\b`) nocase
not re.regex(principal.process.command_line, `\\Windows\\System32\\`) nocase

```
### Dashboard

This syntax incorporates `match` and `outcome` sections to calculate event volume over time. The `timestamp.get_timestamp()` function buckets results by day for trend visualization.
```
metadata.event_type = "PROCESS_LAUNCH"
re.regex(principal.process.command_line, `\bsvchost(\.exe)?\b`) nocase
not re.regex(principal.process.command_line, `\\Windows\\System32\\`) nocase
$date = timestamp.get_timestamp(metadata.event_timestamp.seconds)

match:
  $date

outcome:
  $event_count = count(metadata.id)

```
### Network range and logic
Use case: Filtering activity based on specific IP subnets (CIDR) and matching against multiple possible hostnames.
Key concepts:  `net.ip_in_range_cidr()`: This function checks if a given IP address is contained within a given Classless Inter-Domain Routing (CIDR) Subnet for subnet matching and the or operator for string arrays. Logical operator `OR`: Used to combine multiple conditions. Conditions within the event section are implicitly combined with `AND` The `OR` operator checks against multiple possible hostnames.
#### Example: Single-event matching (IP range)
### Rule

The following example shows a single-event rule that searches for matches between two specific hostnames and a specific range of IP addresses:
```
rule OrsAndNetworkRange {
meta:
  author = "noone@altostrat.com"

events:
  // Checks CIDR ranges.
  net.ip_in_range_cidr($e.principal.ip, "203.0.113.0/24")

  // Detection when the hostname field matches either value using or.
  $e.principal.hostname = /pbateman/ or $e.principal.hostname = /sspade/

condition:
  $e
}

```
### Search

The following query example identifies events where a specific IP address falls within a defined CIDR range and the hostname matches a specific user pattern:
```
net.ip_in_range_cidr(principal.ip, "203.0.113.0/24")

principal.hostname = /pbateman/ or principal.hostname = /sspade/

```
Because this is a search query, not a detection rule, the entire event is returned automatically if filters are met. A `match` section groups data by `principal.ip` and `principal.hostname`. A `condition` section isn't required, and event variables (`$e`) are omitted because no event correlation is performed.
### Dashboard

The following example query aggregates results by grouping unique IP and hostname pairs:
```
net.ip_in_range_cidr(principal.ip, "203.0.113.0/24")

principal.hostname = /pbateman/ or principal.hostname = /sspade/

match:
  principal.ip, principal.hostname

```
### Regular expressions in queries
Use case: Searches for flexible string patterns (for example, specific domains in emails) while ignoring capitalization. This is most commonly used in Search and Rules.
Key logic: Uses `/regex/ nocase` for basic matches and the `re.regex()` function for complex field analysis.
#### Example: Email filtering
### Rule

The following YARA-L 2.0 regular expression example searches for events with emails received from the `altostrat.com` domain. Because `nocase` has been added to the `$host` variable `regex` comparison and the `regex` function, these comparisons are case-insensitive.
```
rule RegexRuleExample {
meta:
  author = "noone@altostrat.com"

events:
  $e.principal.hostname = $host
  $host = /.*HoSt.*/ nocase
  re.regex($e.network.email.from, `.*altostrat\.com`) nocase

match:
  $host over 10m

condition:
  #e > 10
}

```
### Search

In the Search interface, this logic is used for high-fidelity threat hunting and data exploration. Rather than waiting for an automated alert, analysts can manually query the UDM to uncover specific instances of hostnames matching a naming convention alongside targeted email domains. This is the primary method for validating the volume of these events before promoting them into a persistent detection rule.
```
principal.hostname = $host
$host = /.*HoSt.*/ nocase
re.regex(network.email.from, `.*altostrat\.com`) nocase
match:
 $host over 10m
 ```

```
 
### Dashboard

The following logic identifies patterns of interest by aggregating `hostname` and `email` telemetry into 10-minute (`10m`) buckets. When used in a Dashboard, this logic lets analysts visualize the communication frequency from specific assets (matching `host`) to the `altostrat.com` domain. This view is essential for monitoring internal data movement trends and identifying top talkers across critical infrastructure. 
```
principal.hostname = $host
$host = /.*HoSt.*/ nocase
re.regex(network.email.from, `.*altostrat\.com`) nocase

match:
$host over 10m
  ```

```
#### Example: Hostname regular expression
### Rule

The following example identifies any log activity where the principal `hostname` is identified as either a web (`webserver`) or development (`devserver`) server. It uses a case-insensitive regular expression to make sure that variations in naming conventions don't result in missed detections.
```
rule WebServerOrDevServerActivity {
meta:
 author = "Alex"
 description = "Detects events where the principal hostname is 'webserver' or 'devserver', ignoring case."
 severity = "Informational"

events:
 $e.principal.hostname = /webserver|devserver/ nocase

condition:
 $e
}

```
### Search

In the following example, `principal.hostname = /webserver|devserver/ nocase` matches hostnames like `"WebServer01"`, `"devserver-test"`, `"MyWebServers"`. This is a common use case to find a specific event.
```
// Use /regex/ followed by nocase for a case-insensitive match
principal.hostname = /webserver|devserver/ nocase

```
### Dashboard

While this specific example isn't visualized in a dashboard, this rule provides active alerting and persistent detection. Unlike a dashboard, which requires manual review, this ensures that every instance of activity on these servers is automatically flagged and recorded in the detection engine for immediate searchability.
#### Example: Search raw logs
### Rule

While you use manual search for point-in-time investigations, detection rules provide continuous, 24/7 telemetry monitoring. You can convert a successful search query into a YARA-L rule to automate the alerting process.
Key benefits of rules:  Real-time alerting: Automatically flags matches as they enter the system. Persistence: Eliminates the need for manual re-entry of search terms. Outcome actions: Directly feeds into the detection view for analyst triage and incident response.  Note: For ad hoc hunting or initial data discovery, refer to the Search tab. To promote a search to a permanent detection, follow the Build a rule workflow.
### Search

Security analysts frequently use `regex` to search through raw, unparsed logs within Google SecOps. This action allows for flexible pattern matching to find specific artifacts, even if they aren't fully structured or indexed. The syntax uses forward slashes:
`raw = /host/`
This query returns any raw log line where the sequence of characters `"host"` appears. Examples of matching raw log content might include `"hostname": "myhost123"`. Note: This is a search only for investigation purposes.
### Dashboard

There's no dedicated dashboard variant for this specific event type. To visualize these detections at scale, you can:  Map the `metadata.event_type` to a bar or pie chart within the Dashboard builder. Track the frequency of these events over 7, 30, or 90-day windows to identify anomalies in user behavior.
### Repeated fields with universal conditions
Use case: Audit events that contain lists of data (repeated fields) to make sure no trusted exceptions are present, for example, verify that every IP address associated with a login is outside of a known secure range.
Key logic: Uses the `all` operator to evaluate every element in a repeated field against a specific condition and demonstrates how assigning a repeated field to a placeholder variable (for example, `$ip`) creates a distinct detection for each unique value in the list.
#### Example: Suspicious login IP validation
### Rule

The following rule searches for login events where all source IP addresses don't match an IP address known to be secure within a timespan of five minutes (`5m`).
```
rule SuspiciousIPLogins {
meta:
  author = "alice@example.com"

events:
  $e.metadata.event_type = "USER_LOGIN"

  // Detects if all source IP addresses in an event do not match "100.97.16.0"
  // For example, if an event has source IP addresses
  // ["100.97.16.1", "100.97.16.2", "100.97.16.3"],
  // it will be detected since "100.97.16.1", "100.97.16.2",
  // and "100.97.16.3" all do not match "100.97.16.0".

  all $e.principal.ip != "100.97.16.0"

  // Assigns placeholder variable $ip to the $e.principal.ip repeated field.
  // There will be one detection per source IP address.
  // For example, if an event has source IP addresses
  // ["100.97.16.1", "100.97.16.2", "100.97.16.3"],
  // there will be one detection per address.

  $e.principal.ip = $ip

match:
  $ip over 5m

condition:
  $e
}

```
### Search

```
metadata.event_type = "USER_LOGIN"

// Detects if all source IP addresses in an event do not match "100.97.16.0"
// For example, if an event has source IP addresses
// ["100.97.16.1", "100.97.16.2", "100.97.16.3"],
// it will be detected since "100.97.16.1", "100.97.16.2",
// and "100.97.16.3" all do not match "100.97.16.0".

all principal.ip != "100.97.16.0"

// Assigns placeholder variable $ip to the $e.principal.ip repeated field.
// There will be one detection per source IP address.
// For example, if an event has source IP addresses
// ["100.97.16.1", "100.97.16.2", "100.97.16.3"],
// there will be one detection per address.

principal.ip = $ip

match:
  $ip over 5m

```
### Dashboard

```
metadata.event_type = "USER_LOGIN"

// Detects if all source IP addresses in an event do not match "100.97.16.0"
// For example, if an event has source IP addresses
// ["100.97.16.1", "100.97.16.2", "100.97.16.3"],
// it will be detected since "100.97.16.1", "100.97.16.2",
// and "100.97.16.3" all do not match "100.97.16.0".

all principal.ip != "100.97.16.0"

// Assigns placeholder variable $ip to the $e.principal.ip repeated field.
// There will be one detection per source IP address.
// For example, if an event has source IP addresses
// ["100.97.16.1", "100.97.16.2", "100.97.16.3"],
// there will be one detection per address.

principal.ip = $ip

match:
  $ip over 5m

```
## Advanced windowing
This section covers multi-stage patterns and detections triggered by activity from other rules.    Topic Examples     Multi-event correlation  Multi-city login detection; Rapid user creation and deletion    Sliding window in queries Detection of missing sequential events   Multi-event queries High-frequency login detection   Multi-event queries with calculated outcomes  Brute force followed by successful login; Time-windowed host matching
### Multi-event correlation
This section shows examples on how to track entities (users or hosts) across multiple events or time windows to identify behavioral patterns.
Use case: Detects impossible travel where a single user logs in from two or more cities in under five (`5m`) minutes.
Key logic: Use the `match` section to group by `$user` and `#city > 1` to find distinct location values.
#### Example: Multi-city login detection
### Rule

The following rule searches for users that have logged in to your enterprise from two or more cities in less than 5 (`5m`) minutes, where `$user` is the `match` variable, `$udm` is the event variable, and `$city` and `$user` are the placeholder variables:
```
rule DifferentCityLogin {
meta:

events:
  $udm.metadata.event_type = "USER_LOGIN"
  $udm.principal.user.userid = $user
  $udm.principal.location.city = $city

match:
  $user over 5m

condition:
  $udm and #city > 1
}

```
The following explanation describes how this rule works:  Groups events with username (`$user`) and returns it (`$user`) when a match is found. Timespan is five minutes (`5m`); only events that are less than 5 minutes (`5m`) apart are correlated. Searches for an event group (`$udm`) whose event type is `USER_LOGIN`. For that event group, the rule calls the user ID as `$user` and the login city as `$city`. Returns a match if the distinct number of `city` values (denoted by `#city`) is greater than `1` in the event group (`$udm`) within the 5-minute (`5m`) time range.
### Search

The following example query runs an equivalent statistical search to identify impossible travel patterns. It groups `USER_LOGIN` events by user within a five-minute (`5m`) window and filters the results to display only instances where multiple distinct cities are detected for a single identity.
```
events:
  metadata.event_type = "USER_LOGIN"
  principal.user.userid = $user
  principal.location.city = $city

match:
  $user over 5m

condition:
  #city > 1

```
### Dashboard

The following example query gives an equivalent dashboard visualization to track potential account compromise. It aggregates `USER_LOGIN` events by user over a five-minute (`5m`) window and filters for instances where a single identity is associated with more than one distinct city (`#city`), which lets you plot these high-risk geographic anomalies over time.
```
events:
  metadata.event_type = "USER_LOGIN"
  principal.user.userid = $user
  principal.location.city = $city

match:
  $user over 5m

condition:
  #city > 1

```
### Rapid user creation and deletion
Use case: Identifies burner accounts created and then deletes them within a 4-hour window.
Key logic: Joins two event types (`USER_CREATION` and `USER_DELETION`) on a shared `$user` variable and compares timestamps.
#### Example: Rapid user creation and deletion
### Rule

The following rule example searches for users who have been created and then deleted within 4 hours (`4h`) where `$create` and `$delete` are the event variables, `$user` is the `match` variable, and there are no placeholder variables:
```
rule UserCreationThenDeletion {
meta:

events:
  $create.target.user.userid = $user
  $create.metadata.event_type = "USER_CREATION"

  $delete.target.user.userid = $user
  $delete.metadata.event_type = "USER_DELETION"

  $create.metadata.event_timestamp.seconds <=
     $delete.metadata.event_timestamp.seconds

match:
  $user over 4h

condition:
  $create and $delete
}

```
### Search

The following example demonstrates a multi-event stats search used to identify rapid account lifecycle changes. This query outputs one row per user within a four-hour window, correlating the creation and deletion of identities.
Because the search defaults to returning any window containing the specified events, a `condition` section isn't required.
```
$create.target.user.userid = $user
$create.metadata.event_type = "USER_CREATION"

$delete.target.user.userid = $user
$delete.metadata.event_type = "USER_DELETION"

$create.metadata.event_timestamp.seconds <=
$delete.metadata.event_timestamp.seconds

match:
  $user over 4h

```
### Dashboard

The following example demonstrates a multi-event dashboard search designed to plot account lifecycle trends over time. By utilizing a tumbling window (`by 4h`), the results are mapped to discrete, non-overlapping time buckets, which is ideal for visualization.
This variation includes an `outcome` section to calculate the distinct count of creation events within each window. Unlike the previous search, this version doesn't require specific event variables to be returned, because the focus is on aggregate statistical values rather than individual log lines.
```
$create.target.user.userid = $user
$create.metadata.event_type = "USER_CREATION"

$delete.target.user.userid = $user
$delete.metadata.event_type = "USER_DELETION"

$create.metadata.event_timestamp.seconds <=
$delete.metadata.event_timestamp.seconds

match:
  $user by 4h

outcome:
  $event_count = count_distinct($create.metadata.id)

```
### Sliding window in queries
Use case: To detect a potential security issue where an initial event (from `firewall_1`) isn't followed by an expected subsequent event (from `firewall_2`) on the same host within a specific timeframe.
Key logic:  Pivot event: The rule centers around events from `firewall_1`, designated as `$e1`. Each time an `$e1` event occurs, it acts as a pivot. Time window: The `match` section (`$host over 10m after $e1`) defines a 10-minute window that begins immediately after each `$e1` event. This window slides with each new `$e1` event. Correlation: Events are grouped by hostname (`$host`). Condition for detection (`$e1` and `$e2`): A detection is triggered for a given host if:  An event from `firewall_1` (`$e1`) is present. `AND`, within the 10-minute window following that specific `$e1` event, `NO` event from `firewall_2` (`$e2`) is found for the same host.
#### Example: Detection of missing sequential events
### Rule

The following example identifies instances where a secondary event fails to occur after a primary trigger. By using the `!$e2` condition within a 10-minute window, this rule flags missing telemetry—specifically when a firewall log is seen at one location but doesn't appear at the next expected hop, which indicates a potential visibility gap or traffic drop.
```
rule MissingSequentialEvent {
meta:
  author = "alice@example.com"

events:
  $e1.metadata.product_name = "firewall_1"
  $e1.principal.hostname = $host

  $e2.metadata.product_name = "firewall_2"
  $e2.principal.hostname = $host

match:
// $e1 is the pivot; the 10-minute window starts at the $e1 timestamp
  $host over 10m after $e1

condition:
  $e1 and !$e2
}

```
### Search

The following example demonstrates a sequential search used to identify gaps in telemetry between two sources. By using `$e1` as a pivot, the search looks for a primary firewall event that isn't followed by a corresponding event on a second firewall within 10 minutes. This is a highly effective way to manually hunt for "black holes" in network traffic or logging failures during an investigation.
```
$e1.metadata.product_name = "firewall_1"
$e1.principal.hostname = $host

$e2.metadata.product_name = "firewall_2"
$e2.principal.hostname = $host

match:
// $e1 is the pivot; the 10-minute window starts at the $e1 timestamp
  $host over 10m after $e1

condition:
  $e1 and !$e2

```
### Dashboard

The following example provides a visibility gap analysis designed for a dashboard view. By aggregating instances where a secondary event fails to follow a primary one, you can visualize the reliability of your logging pipeline over time. Plotting these "missing" events helps identify persistent dead zones in network visibility or configuration issues across specific hostnames.
```
$e1.metadata.product_name = "firewall_1"
$e1.principal.hostname = $host

$e2.metadata.product_name = "firewall_2"
$e2.principal.hostname = $host

match:
// $e1 is the pivot; the 10-minute window starts at the $e1 timestamp
  $host over 10m after $e1

condition:
  $e1 and !$e2

```
### Multi-event queries
Use case: Identify high frequency or brute force activity by tracking a single entity (for example, a user or host) across multiple occurrences of an event within a specific time window.
Key logic: Uses a `match` section to group events by a specific variable and a `condition` section to check for a threshold count (for example, `#e >= 10`) within the defined time range.
A typical multi-event rule includes:  Event variables to distinguish between events. A `match` section that specifies the time range over which events need to be grouped. A `condition` section that specifies what condition should trigger the detection and check for the existence of multiple events.
In Search, multi-event queries are defined by more than one event in a query. For Rules, there are two ways to define this:
Multiple events: (for example, `event1 = successful login, event2 = failed login`).
Condition-based triggers: The condition is stated to trigger only when multiple events meet the criteria (for example, `event1 > 10`). This type of rule also needs to include an `outcome` section.  Note: Rules with a `match` and `condition` section that includes `outcome` variables, in addition to what exists on one event, are classified as multi-event rules. With these rules, detection generation logic depends on all events in a `match` window (for example, many events), rather than any event in a `match` window (for example, single event).
#### Example: High-frequency login detection
### Rule

The following rule searches for a user who has logged in at least 10 times in less than 10 minutes:
```
rule MultiEventRule {
meta:
  author = "noone@altostrat.com"

events:
  $e.metadata.event_type = "USER_LOGIN"
  $e.principal.user.userid = $user

match:
  $user over 10m

condition:
  #e >= 10
}

```
### Search

The following example uses a multi-event stats search to identify high-frequency login activity. It flags any instance where a single user generates 10 or more login events within a 10-minute (`10m`) window.
```
$e.metadata.event_type = "USER_LOGIN"
$e.principal.user.userid = $user

match:
  $user by 10m

condition:
  #e >= 10

```
### Dashboard

The following example uses a multi-event search to monitor for potential account compromise. By correlating login attempts within a 10-minute sliding window, it identifies instances where a specific user and host experience multiple failed logins followed by a successful one, allowing you to visualize high-risk authentication patterns in real time.
```
$e.metadata.event_type = "USER_LOGIN"
$e.principal.user.userid = $user

match:
  $user by 10m

condition:
  #e >= 10

```
### Multi-event queries with calculated outcomes
Use case: Apply conditional logic to set a `risk_score` based on asset severity or network volume.
Key logic: Uses the `outcome` section to calculate variables and the condition section to filter by those variables.
#### Example: Brute force followed by successful login
The following example uses the `outcome` section to count event within a `match` window. This query generates the same output as standard multi-event query, but demonstrates how to incorporate calculated variables into your detection logic.
### Rule

```
rule PossibleBruteForceThenSuccessfulLogin {
meta:
  author = "Alex"
  description = "Detects multiple failed login attempts followed by a successful login for the same user and host within a 10-minute window."
  severity = "High"
  tactic = "Credential Access"

events:
  // Define the first type of event: Failed Login
  // We use $failed to represent any event matching these criteria.
  $failed.metadata.event_type = "USER_LOGIN"
  $failed.security_result.action = "FAIL"
  // Extract common fields to correlate on
  $failed.target.user.userid = $user
  $failed.principal.hostname = $hostname

  // Define the second type of event: Successful Login
  // We use $success to represent any event matching these criteria.
  $success.metadata.event_type = "USER_LOGIN"
  $success.security_result.action = "ALLOW"
  // Correlate using the same user and hostname placeholders
  $success.target.user.userid = $user
  $success.principal.hostname = $hostname

match:
  // This section is key for multi-event rules. It groups events:
  // - By the common placeholder variables: $user and $hostname.
  // - Within a time window: by 10m.
  // The rule will evaluate all events matching $failed or $success that share the same $user and $hostname within any given 10-minute period.
  $user, $hostname by 10m

outcome:
  // Calculate aggregate values from the events within the match window.
  $failed_login_count = count($failed.metadata.id)
  $successful_login_count = count($success.metadata.id)

condition:
  // The conditions that must be met *within each matched group* ($user, $hostname over 10m).
  // - #failed >= 5: There must be 5 or more events matching the $failed criteria.
  // - #success >= 1: There must be at least 1 event matching the $success criteria.
  #failed >= 5 and #success >= 1
}

```
### Search

```
// Define the first type of event: Failed Login
// We use $failed to represent any event matching these criteria.
$failed.metadata.event_type = "USER_LOGIN"
$failed.security_result.action = "FAIL"
// Extract common fields to correlate on
$failed.target.user.userid = $user
$failed.principal.hostname = $hostname

// Define the second type of event: Successful Login
// We use $success to represent any event matching these criteria.
$success.metadata.event_type = "USER_LOGIN"
$success.security_result.action = "ALLOW"
// Correlate using the same user and hostname placeholders
$success.target.user.userid = $user
$success.principal.hostname = $hostname

match:
  // This section is key for multi-event rules. It groups events:
  // - By the common placeholder variables: $user and $hostname.
  // - Within a sliding time window: over 10m.
  // The rule will evaluate all events matching $failed or $success that share
  // the same $user and $hostname within any given 10-minute period.
  $user, $hostname over 10m

```
### Dashboard

```
// Define the first type of event: Failed Login
// We use $failed to represent any event matching these criteria.
$failed.metadata.event_type = "USER_LOGIN"
$failed.security_result.action = "FAIL"
// Extract common fields to correlate on
$failed.target.user.userid = $user
$failed.principal.hostname = $hostname

// Define the second type of event: Successful Login
// We use $success to represent any event matching these criteria.
$success.metadata.event_type = "USER_LOGIN"
$success.security_result.action = "ALLOW"
// Correlate using the same user and hostname placeholders
$success.target.user.userid = $user
$success.principal.hostname = $hostname

match:
  // This section is key for multi-event rules. It groups events:
  // - By the common placeholder variables: $user and $hostname.
  // - Within a sliding time window: over 10m.
  // The rule will evaluate all events matching $failed or $success that share
  // the same $user and $hostname within any given 10-minute period.
  $user, $hostname over 10m

```
#### Example: Time-windowed host matching
### Rule

The following rule looks at two events to get the value of $hostname. If the value of `$hostname` matches over a 5-minute (`5m`) period, then a severity score is applied. When including a time period in the `match` section, the rule checks within the specified time period.
```
rule OutcomeRuleMultiEvent {
meta:
  author = "Google Cloud Security"
events:
  $u.udm.principal.hostname = $hostname
  $asset_context.graph.entity.hostname = $hostname

  $severity = $asset_context.graph.entity.asset.vulnerabilities.severity

match:
  $hostname over 5m

outcome:
  $risk_score =
    max(
        100
      + if($hostname = "my-hostname", 100, 50)
      + if($severity = "HIGH", 10)
      + if($severity = "MEDIUM", 5)
      + if($severity = "LOW", 1)
    )

  $asset_id_list =
    array(
      if($u.principal.asset_id = "",
          "Empty asset id",
          $u.principal.asset_id
      )
    )

  $asset_id_distinct_list = array_distinct($u.principal.asset_id)

  $asset_id_count = count($u.principal.asset_id)

  $asset_id_distinct_count = count_distinct($u.principal.asset_id)

condition:
  $u and $asset_context and $risk_score > 50 and not arrays.contains($asset_id_list, "id_1234")
}

```
### Search

```
 // Define the first type of event: Failed Login
 // We use $failed to represent any event matching these criteria.
 $failed.metadata.event_type = "USER_LOGIN"
 $failed.security_result.action = "FAIL"
 // Extract common fields to correlate on
 $failed.target.user.userid = $user
 $failed.principal.hostname = $hostname

 // Define the second type of event: Successful Login
 // We use $success to represent any event matching these criteria.
 $success.metadata.event_type = "USER_LOGIN"
 $success.security_result.action = "ALLOW"
 // Correlate using the same user and hostname placeholders
 $success.target.user.userid = $user
 $success.principal.hostname = $hostname

match:
 // This section is key for multi-event rules. It groups events:
 // - By the common placeholder variables: $user and $hostname.
 // - Within a sliding time window: over 10m.
 // The rule will evaluate all events matching $failed or $success that share
 // the same $user and $hostname within any given 10-minute period.
 $user, $hostname over 10m

outcome:
 // Calculate aggregate values from the events within the match window.
 $failed_login_count = count($failed.metadata.id)
 $successful_login_count = count($success.metadata.id)
 ```

```
 
### Dashboard

```
// Define the first type of event: Failed Login
// We use $failed to represent any event matching these criteria.
$failed.metadata.event_type = "USER_LOGIN"
$failed.security_result.action = "FAIL"
// Extract common fields to correlate on
$failed.target.user.userid = $user
$failed.principal.hostname = $hostname

// Define the second type of event: Successful Login
// We use $success to represent any event matching these criteria.
$success.metadata.event_type = "USER_LOGIN"
$success.security_result.action = "ALLOW"
// Correlate using the same user and hostname placeholders
$success.target.user.userid = $user
$success.principal.hostname = $hostname

match:
// This section is key for multi-event rules. It groups events:
// - By the common placeholder variables: $user and $hostname.
// - Within a sliding time window: over 10m.
// The rule will evaluate all events matching $failed or $success that share
// the same $user and $hostname within any given 10-minute period.
$user, $hostname over 10m

outcome:
// Calculate aggregate values from the events within the match window.
$failed_login_count = count($failed.metadata.id)
$successful_login_count = count($success.metadata.id)

```
  
## Composite detections
 
Composite detections enhance threat detection by using composite rules. These composite rules use detections from other rules as their input. This enables the detection of complex threats that individual rules might not detect. For more information, see Composite detections overview. Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms.    Topic Examples     High-risk filtering Administrative user detection   Aggregation and thresholding Risk aggregation   Tactic aggregation MITRE Tactic aggregation   Sequential composite detections Brute-force attempt followed by successful login   Context-aware detections Threat intelligence enrichment   Co-occurrence detections Privilege escalation and exfiltration co-occurrence    
### High-risk filtering
 
Use case: Filter existing detections for high-risk attributes, such as activity involving administrative accounts. 
Key logic: Operates on outcomes or metadata fields within existing findings. 
High-risk filtering composite detections are the simplest form of a composite detection that operates on fields within detection findings, such as outcome variables or rule metadata. They help filter detections for conditions that may indicate higher risk, such as an administrator user or a production environment. 
#### Example: Administrative user detection
  
### Rule

The following composite rule searches for any existing detections where the actor is identified as an administrative user and applies a standardized risk score. 
```
rule composite_admin_detection {
meta:
rule_name = "Detection with Admin User"
author = "Google Cloud Security"
description = "Composite rule that looks for any detections where the actor is an admin user"
severity = "Medium"

events:
$rule_name = $d.detection.detection.rule_name
$principal_user = $d.detection.detection.variables["principal_users"]
$principal_user = /admin|root/ nocase

match:
$principal_user over 1h
outcome:
$risk_score = 75
$upstream_rules = array_distinct($rule_name)

condition:
$d
}

```
 
### Search

The following statistical search identifies and aggregates activity for high-privilege accounts. It's designed to surface all unique rule names that have triggered detections involving "admin" or "root" users. 
In this specific query, the time window is removed to perform a single statistical analysis across all detections within the selected timeframe. Additionally, since this is an unaggregated search focused on existing detection data, the events section, event variables, and condition section are not required. 
```
$rule_name = detection.detection.rule_name
$principal_user = detection.detection.variables["principal_users"]
$principal_user = /admin|root/ nocase

match:
$principal_user

outcome:
$upstream_rules = array_distinct($rule_name)

```
 
### Dashboard

This dashboard query lets you visualize which specific rules are most frequently detecting admin-related activity. It's designed to provide a high-level overview of detection trends across your environment. 
Note the change in the `match` variable and `outcome` aggregation compared to previous examples. This query groups the results by rule name and calculates a count of the admin users detected for each. 
```
$rule_name = detection.detection.rule_name
$principal_user = detection.detection.variables["principal_users"]
$principal_user = /admin|root/ nocase

match:
$rule_name

outcome:
$admin_detections = count($principal_user)

```
  
### Aggregation and thresholding
 
Use case: Identify users or hosts generating a high volume of alerts or accumulating significant risk scores over time. 
Key logic: Uses `sum()` or `count_distinct()` to analyze aggregated detection data. 
Aggregation composite detection rules let you group detection findings based on shared attributes, such as a hostname or username, and analyze the aggregated data. The following are common use cases:  Identifying users who generate a high volume of security alerts or aggregated risk. Detecting hosts with unusual activity patterns by aggregating related detections.  
#### Example: Risk aggregation
  
### Rule

This rule aggregates the risk score of a single user over a 48-hour window. It identifies users whose cumulative risk across multiple detections exceeds a specific threshold. 
In this updated logic, `detection.detection.outcomes` is replaced by map field variables, which store both `match` and `outcome` variables. Additionally, the `$principal_users` outcome variable is removed because each detection contains exactly one match variable value, which is already captured. 
```
rule composite_risk_aggregation {
meta:
rule_name = "Risk Aggregation Composite"
author = "Google Cloud Security"
description = "Composite detection that aggregates risk of a user over 48 hours"
severity = "High"

events:
$rule_name = $d.detection.detection.rule_name
$principal_user = $d.detection.detection.outcomes["principal_users"]
$risk = $d.detection.detection.risk_score

match:
$principal_user over 48h

outcome:
$risk_score = 90
$cumulative_risk = sum($risk)
$upstream_rules = array_distinct($rule_name)

condition:
$d and $cumulative_risk > 500
}

```
 
### Search

This statistical search aggregates detection data to calculate a user's total risk over a 48-hour period. It outputs one row per principal user for each window, providing a high-level view of account risk across multiple detection types. 
In this variation, event variables aren't required. While the rules engine automatically filters out detections without a principal user, this search requires an explicit filter (`$principal_user != ""`) to make sure the results only include populated data. By default, the query returns results only when one or more detections are present for a given user. 
```
$rule_name = detection.detection.rule_name
$principal_user = detection.detection.variables["principal_user"]
$principal_user != ""
$risk = detection.detection.risk_score

match:
$principal_user over 48h

outcome:
$risk_score = 90
$cumulative_risk = sum($risk)
$upstream_rules = array_distinct($rule_name)

condition:
$cumulative_risk > 500

```
 
### Dashboard

This variation is designed specifically for dashboards to plot user risk and detection activity over time. It aggregates data into discrete buckets, making it ideal for visualizing trends such as the volume of unique rules triggered or the total count of detections per user. 
In this query, the window is switched from a sliding (hop) window to a tumbling window (`by 48h`). This ensures that data points map to non-overlapping time segments, which provides a cleaner visualization for time-series charts. Like other unaggregated searches, event variables aren't required, and the `outcome` section is expanded to include distinct counts for both rule names and detection IDs. 
```
$rule_name = detection.detection.rule_name
$principal_user = detection.detection.variables["principal_user"]
$principal_user != ""
$risk = detection.detection.risk_score

match:
$principal_user by 48h

outcome:
$cumulative_risk = sum($risk)
$rule_count = count_distinct($rule_name)
$detection_count = count_distinct(detection.id)

condition:
$cumulative_risk > 500

```
  
### Tactic aggregation
 
Use case: Identify users whose activity has triggered detections across multiple distinct MITRE ATT&CK tactics, suggesting a progressing attack lifecycle (for example, shifting from Initial Access to Exfiltration). 
Key logic: Uses `count_distinct($tactic)` to trigger only when a user crosses a specific threshold of different tactics within a 48-hour window. 
#### Example: MITRE tactic aggregation
  
### Rule

```
rule composite_tactic_aggregation {
meta:
rule_name = "MITRE Tactic Aggregation Composite"
author = "Google Cloud Security"
description = "Composite detection that detects if a user has triggered detections over multiple mitre tactics."
severity = "Medium"

events:
$principal_user = $d.detection.detection.outcomes["principal_users"]
$tactic = $d.detection.detection.outcomes["mitre_tactic"]
$rule_name = $d.detection.detection.rule_name

match:
$principal_user over 48h

outcome:
$mitre_tactics_count = count_distinct($tactic)
$mitre_tactics = array_distinct($tactic)
$calculated_risk = 50 + (15 * $mitre_tactics_count)
$upstream_rules = array_distinct($rule_name)

condition:
$d and $mitre_tactics_count > 1 }

```
 
### Search

The following example demonstrates a search variant designed for security developers who need to correlate existing detections and apply dynamic risk weighting. This query logic extracts MITRE ATT&CK tactics and user information from the `detection` data source, groups the activity by the principal user, and calculates a custom risk score based on the diversity of the observed tactics. 
```
detection.detection.outcomes.key = "principal_users"
detection.detection.outcomes.key = "mitre_tactic"
$principal_user = detection.detection.outcomes["principal_users"]
$tactic = detection.detection.outcomes["mitre_tactic"]
$rule_name = detection.detection.rule_name

match:
$principal_user

outcome:
$mitre_tactics_count = count_distinct($tactic)
$mitre_tactics = array_distinct($tactic)
$upstream_rules = array_distinct($rule_name)
$calculated_risk = 50 + (15 * $mitre_tactics_count)
$risk_score = if($calculated_risk > 100, 100,   $calculated_risk)

```
 
### Dashboard

The following example illustrates a Dashboards variant of the same detection analysis logic. When used within Google SecOps Dashboards, this query allows developers to visualize high-risk users by correlating detection outcomes across different rules. The logic extracts the principal user and MITRE tactics, aggregates the findings, and applies a capped risk score to help prioritize investigative efforts directly within a dashboard widget. 
```
detection.detection.outcomes.key = "principal_users"
detection.detection.outcomes.key = "mitre_tactic"
$principal_user = detection.detection.outcomes["principal_users"]
$tactic = detection.detection.outcomes["mitre_tactic"]
$rule_name = detection.detection.rule_name

match:
$principal_user

outcome:
$mitre_tactics_count = count_distinct($tactic)
$mitre_tactics = array_distinct($tactic)
$upstream_rules = array_distinct($rule_name)
$calculated_risk = 50 + (15 * $mitre_tactics_count)
$risk_score = if($calculated_risk > 100, 100,   $calculated_risk)
  ```

```
### Sequential composite detections
Use case: Identify critical attack patterns where the order of operations is essential, for example, detecting a successful account login that occurs only after a series of brute-force attempt alerts from the same IP address.
Key logic: Correlates a prior detection with a subsequent raw UDM event by joining them on a common variable (for example, `$bruteforce_ip`) and using a timestamp comparison to ensure the events occurred in the correct sequence.
Sequential composite detections identify patterns of related events where the sequence of detections is important, such as a brute-force login attempt detection, followed by a successful login. These patterns can involve multiple base detections or a combination of base detections and events.
#### Example: Brute-force attempt followed by successful login
### Rule

The following composite rule identifies patterns of related events where the sequence is important. It specifically looks for a Google Workspace brute-force detection followed by a successful login event from the same source IP within a 24-hour window.
```
rule composite_bruteforce_login {
meta:
  rule_name = "Bruteforce Login Composite"
  author = "Google Cloud Security"
  description = "Detects when an IP address associated with a Workspace brute force attempt successfully logs in"
  severity = "High"

events:
  $bruteforce_detection.detection.detection.rule_name = /Workspace Anomalous Failed Logins/
  $bruteforce_ip = $bruteforce_detection.detection.detection.variables["principal_ips"]

  $login_event.metadata.product_name = "login"
  $login_event.metadata.product_event_type = "login_success"
  $login_event.metadata.vendor_name = "Google Workspace"
  $login_ip = $login_event.principal.ip

  // Ensure the brute force detection and successful login occurred from the same IP
  $login_ip = $bruteforce_ip

  $target_account = $login_event.target.user.email_addresses

  // Ensure the brute force detection occurred before the successful login
  $bruteforce_detection.detection.detection_time.seconds < $login_event.metadata.event_timestamp.seconds

match:
  $bruteforce_ip over 24h

outcome:
  $risk_score = 90
  $principal_users = array_distinct($target_account)

condition:
  $bruteforce_detection and $login_event
}

```
### Search

```
$bruteforce_detection.detection.detection.rule_name = /Workspace Anomalous Failed Logins/
$bruteforce_ip = $bruteforce_detection.detection.detection.variables["principal_ips"]

$login_event.metadata.product_name = "login"
$login_event.metadata.product_event_type = "login_success"
$login_event.metadata.vendor_name = "Google Workspace"
$login_ip = $login_event.principal.ip

// Ensure the brute force detection and successful login occurred from the same IP
$login_ip = $bruteforce_ip

$target_account = $login_event.target.user.email_addresses

// Ensure the brute force detection occurred before the successful login
$bruteforce_detection.detection.detection_time.seconds < $login_event.metadata.event_timestamp.seconds

match:
  $bruteforce_ip over 24h

outcome:
  $principal_users = array_distinct($target_account)

condition:
  $bruteforce_detection and $login_event

```
### Dashboard

Dashboards focus on visualizing raw event data, whereas the composite detection logic correlates existing detection alerts with subsequent events. This multi-layered analysis is optimized for the detection engine rather than real-time dashboard widgets.
### Context-aware detections
Use case: Enrich existing detections with external threat intelligence to verify if an alert involves known malicious entities, for example, checking if an IP address flagged in a security detection is also listed in a global TOR exit node threat feed.
Key logic: Uses composite rules to join detection findings with `GLOBAL_CONTEXT` graph data (for example, Google Cloud Threat Intelligence feeds) by matching a shared attribute like an IP address.
Context-aware composite detections enrich detections with additional context, such as IP addresses found in threat feeds.
#### Example: Threat intelligence enrichment
### Rule

The following composite rule automatically adds additional context from the TOR intel feed to your existing detections. It correlates an IP address found in a prior detection with the TOR Exit Nodes feed to elevate the severity and risk score of the finding.
```
rule composite_tor_enrichment {
meta:
  rule_name = "Detection with IP from TOR Feed"
  author = "Google Cloud Security"
  description = "Adds additional context from the TOR intel feed to detections"
  severity = "High"

events:
  $rule_name = $d.detection.detection.rule_name

  $gcti.graph.metadata.entity_type = "IP_ADDRESS"
  $gcti.graph.metadata.vendor_name = "Google Cloud Threat Intelligence"
  $gcti.graph.metadata.source_type = "GLOBAL_CONTEXT"
  $gcti.graph.metadata.product_name = "GCTI Feed"
  $gcti.graph.metadata.threat.threat_feed_name = "Tor Exit Nodes"

  $detection_ip = $d.detection.detection.variables["principal_ips"]
  $detection_ip = $gcti.graph.entity.ip

match:
  $detection_ip, $rule_name over 1h

outcome:
  $risk_score = 80

condition:
  $d and $gcti
}

```
### Search

 ``` $rule_name = $d.detection.detection.rule_name 
$gcti.graph.metadata.entity_type = "IP_ADDRESS" $gcti.graph.metadata.vendor_name = "Google Cloud Threat Intelligence" $gcti.graph.metadata.source_type = "GLOBAL_CONTEXT" $gcti.graph.metadata.product_name = "GCTI Feed" $gcti.graph.metadata.threat.threat_feed_name = "Tor Exit Nodes" 
$detection_ip = $d.detection.detection.variables["principal_ips"] $detection_ip = $gcti.graph.entity.ip 
match: $detection_ip, $rule_name over 1h 
condition: $d and $gcti ``` 
### Dashboard
Note: Dashboard support for this detection source is unavailable.
### Co-occurrence detections
Use case: Detect a combination of related tactics triggered by the same entity within a specific timeframe, for example, identifying a user who has triggered both a privilege escalation detection and a data exfiltration detection within 48 hours.
Key logic: Uses a form of aggregation to correlate multiple distinct detection types by joining them on a shared entity variable (for example, `$pe_user`) within the `match` section.
Co-occurrence composite detections are a form of aggregation that can detect a combination of related events, such as a combination of privilege escalation and data exfiltration detections triggered by a user.
#### Example: Privilege escalation and exfiltration co-occurrence
### Rule

The following composite rule searches for a specific sequence or combination of detections—privilege escalation followed by exfiltration—associated with the same user over a 48-hour window.
```
rule composite_privesc_exfil_sequential {
meta:
  rule_name = "Privilege Escalation and Exfiltration Composite"
  author = "Google Cloud Security"
  description = "Looks for a detection sequence of privilege escalation followed by exfiltration."
  severity = "High"

events:
  $privilege_escalation.detection.detection.rule_labels["tactic"] = "TA0004"
  $exfiltration.detection.detection.rule_labels["tactic"] = "TA0010"

  $privesc_user = $privilege_escalation.detection.detection.variables["principal_users"]
  $exfil_user = $exfiltration.detection.detection.variables["principal_users"]

  $privesc_user = $exfil_user

  $privilege_escalation.detection.detection_time.seconds < $exfiltration.detection.detection_time.seconds

match:
  $privesc_user over 48h

outcome:
  $risk_score = 75
  $privesc_rules = array_distinct($privilege_escalation.detection.detection.rule_name)
  $exfil_rules = array_distinct($exfiltration.detection.detection.rule_name)

condition:
  $privilege_escalation and $exfiltration
}

```
### Search

```
$privilege_escalation.detection.detection.rule_labels["tactic"] = "TA0004"
$exfiltration.detection.detection.rule_labels["tactic"] = "TA0010"

$privesc_user = $privilege_escalation.detection.detection.variables["principal_users"]
$exfil_user = $exfiltration.detection.detection.variables["principal_users"]

$privesc_user = $exfil_user

$privilege_escalation.detection.detection_time.seconds < $exfiltration.detection.detection_time.seconds

match:
  $privesc_user over 48h

outcome:
  $privesc_rules = array_distinct($privilege_escalation.detection.detection.rule_name)
  $exfil_rules = array_distinct($exfiltration.detection.detection.rule_name)

condition:
  $privilege_escalation and $exfiltration

```
### Dashboard
Note: Dashboard support for this detection source is unavailable.
## Outcome and variable management
This section shows examples of calculating risk and normalizing data for downstream consumption.    Topic Examples     Outcome conditionals Filter by calculated risk score   Single-event query with outcome Point-in-time severity tagging   Network-based risk scoring Network-based risk scoring rule   Refactor multi-event logic (pre-refactor) Outcome refactor (pre-refactor)   Refactor multi-event logic (post-refactor) Outcome refactor (post-refactor)   Function-to-placeholder assignment
### Queries with `outcome` section
You can add the optional `outcome` section in a YARA-L 2.0 rule to extract additional information of each detection. In the `condition` section, you can also specify conditionals on outcome variables. You can use the `outcome` section of a detection rule to set variables for downstream consumption. For example, you can set a severity score based on data from the events being analyzed.
For more information, see the following:  Outcome section syntax Condition section syntax Context-aware analysis, `outcome` section
### Outcome conditionals
Use case: Filter detections based on calculated risk scores to reduce noise and ensure only high-confidence or high-severity events trigger alerts. This is useful for suppressing low-risk activity that doesn't meet a specific business threshold.
Key logic: Defines variables in the `outcome` section using conditional math (for example, adding risk based on file size or time of day) and then references those variables in the `condition` section to gate the detection.
#### Example: Filter by calculated risk score
### Rule

In the `condition` section, you can use `outcome` variables that were defined in the `outcome` section. The following example demonstrates how to filter on risk scores to reduce noise in detections by using outcome conditionals.
```
rule OutcomeConditionalRule {
meta:
  author = "alice@example.com"
  description = "Rule that uses outcome conditionals"

events:
  $u.metadata.event_type = "FILE_COPY"
  $u.principal.file.size = $file_size
  $u.principal.hostname = $hostname

  // 1 = Sunday, 7 = Saturday.
  $dayofweek = timestamp.get_day_of_week($u.metadata.collected_timestamp.seconds)

outcome:
  $risk_score =
      if($file_size > 500*1024*1024, 2) + // Files 500MB are moderately risky
      if($file_size > 1024*1024*1024, 3) + // Files over 1G get assigned extra risk
      if($dayofweek=1 or $dayofweek=7, 4) + // Events from the weekend are suspicious
      if($hostname = /highly-privileged/, 5) // Check for files from highly privileged devices

condition:
  $u and $risk_score >= 10
}

```
### Search
Note: This query must be aggregated to use the `condition` section in Search.
```
metadata.event_type = "FILE_COPY"
principal.file.size = $file_size
principal.hostname = $hostname

// 1 = Sunday, 7 = Saturday.
$dayofweek = timestamp.get_day_of_week(metadata.collected_timestamp.seconds)

outcome:
  $risk_score =
      if($file_size > 500*1024*1024, 2) + // Files 500MB are moderately risky
      if($file_size > 1024*1024*1024, 3) + // Files over 1G get assigned extra risk
      if($dayofweek=1 or $dayofweek=7, 4) + // Events from the weekend are suspicious
      if($hostname = /highly-privileged/, 5) // Check for files from highly privileged devices

```
### Dashboard

This query adds the `$hostname` outcome variable to visualize which hosts are associated with each risk score.
```
metadata.event_type = "FILE_COPY"
principal.file.size = $file_size
principal.hostname = $hostname

// 1 = Sunday, 7 = Saturday.
$dayofweek = timestamp.get_day_of_week(metadata.collected_timestamp.seconds)

outcome:
  $host = $hostname
  $risk_score =
      if($file_size > 500*1024*1024, 2) + // Files 500MB are moderately risky
      if($file_size > 1024*1024*1024, 3) + // Files over 1G get assigned extra risk
      if($dayofweek=1 or $dayofweek=7, 4) + // Events from the weekend are suspicious
      if($hostname = /highly-privileged/, 5) // Check for files from highly privileged devices

```
### Single-event query with outcome
Use case: Enrich point-in-time detections with immediate context, such as assigning severity tags based on user lists or file attributes without requiring a time window or event correlation.
Key logic: Uses the `outcome` section in a rule that lacks a `match` section. This lets you extract metadata and perform conditional logic (for example, checking a user against a reference list) for every individual event that meets the criteria.
#### Example: Point-in-time severity tagging
### Rule

The following example demonstrates how to use the `outcome` section in a single-event rule to set variables for downstream consumption, such as setting a severity score based on the specific user and file size involved in a file copy event.
```
rule OutcomeRuleSingleEvent {
meta:
  author = "alice@example.com"
events:
  $u.metadata.event_type = "FILE_COPY"
  $u.principal.file.size = $file_size
  $u.principal.hostname = $hostname

outcome:
  $suspicious_host = $hostname
  $admin_severity = if($u.principal.user.userid in %admin_users, "SEVERE", "MODERATE")
  $severity_tag = if($file_size > 1024, $admin_severity, "LOW")

condition:
  $u
}

```
### Search

The following example identifies file creation events and uses the `outcome` section to dynamically assign severity levels to each result. Unlike multi-event rules, this unaggregated search doesn't require event variables or a `match` section. Instead, it processes each log individually to output `1 row per event`, enriched with custom logic based on file size and user permissions.
```
metadata.event_type = "FILE_CREATION"
principal.file.size = $file_size
principal.hostname = $hostname

outcome:
  $suspicious_host = $hostname
  $admin_severity = if(principal.user.userid in %a1, "SEVERE", "MODERATE")
  $severity_tag = if($file_size > 1024, $admin_severity, "LOW")

```
### Dashboard

A dashboard variant isn't applicable for this example as the primary intent is to tag and enrich individual events. While a dashboard could aggregate these events (for example, calculating the total count of events per severity tag), doing so would obscure the granular, row-level detail that this unaggregated search is designed to surface.
### Network-based risk scoring
Use case: Identify high-risk data transfers by calculating the cumulative volume of network traffic across a group of events. This allows you to identify threats where the total data threshold exceeds a specific limit (for example, `1024` bytes) while simultaneously factoring in the vulnerability severity of the involved assets.
Key logic: Uses the `sum()` aggregate function in the `outcome` section to combine `sent_bytes` and `received_bytes` across all events in a `match` window. For Rules, the query uses an if statement to apply a higher risk score if that sum exceeds a defined threshold.
#### Example: Network-based risk scoring rule
### Rule

The following example demonstrates how to use the `outcome` section to calculate a dynamic risk score based on network activity. By summing the total bytes transferred across an event group, the rule applies a higher priority to matches exceeding a specific data threshold (`1024` bytes) while simultaneously factoring in the vulnerability severity of the involved asset.
```
rule OutcomeRuleMultiEvent {
meta:
  author = "alice@example.com"
events:
  $u.udm.principal.hostname = $hostname
  $asset_context.graph.entity.hostname = $hostname

  $severity = $asset_context.graph.entity.asset.vulnerabilities.severity

match:
  $hostname over 5m

outcome:
  $total_network_bytes = sum($u.network.sent_bytes) + sum($u.network.received_bytes)

  $risk_score = if($total_network_bytes > 1024, 100, 50) +
    max(
      if($severity = "HIGH", 10)
      + if($severity = "MEDIUM", 5)
      + if($severity = "LOW", 1)
    )

  $asset_id_list =
    array(
      if($u.principal.asset_id = "",
          "Empty asset id",
          $u.principal.asset_id
      )
    )

  $asset_id_distinct_list = array_distinct($u.principal.asset_id)

  $asset_id_count = count($u.principal.asset_id)

  $asset_id_distinct_count = count_distinct($u.principal.asset_id)

condition:
  $u and $asset_context and $risk_score > 50 and not arrays.contains($asset_id_list, "id_1234")
}

```
### Search

The following example demonstrates a search variant that correlates UDM network events with asset context from the Entity Context Graph (ECG). It utilizes a 5-minute `match` window to aggregate network traffic by hostname, calculates a risk score based on data volume and vulnerability severity, and applies a conditional filter to exclude specific asset IDs from the final result set.
```
$u.udm.principal.hostname = $hostname
$asset_context.graph.entity.hostname = $hostname

$severity = $asset_context.graph.entity.asset.vulnerabilities.severity

match:
  $hostname over 5m

outcome:
  $total_network_bytes = sum($u.network.sent_bytes) + sum($u.network.received_bytes)

  $risk_score = if($total_network_bytes > 1024, 100, 50) +
    max(
      if($severity = "HIGH", 10)
      + if($severity = "MEDIUM", 5)
      + if($severity = "LOW", 1)
    )

  $asset_id_list =
    array(
      if($u.principal.asset_id = "",
        "Empty asset id",
        $u.principal.asset_id
      )
    )

  $asset_id_distinct_list = array_distinct($u.principal.asset_id)

  $asset_id_count = count($u.principal.asset_id)

  $asset_id_distinct_count = count_distinct($u.principal.asset_id)

condition:
  $u and $asset_context and $risk_score > 50 and not arrays.contains($asset_id_list, "id_1234")

```
### Dashboard

The following example illustrates a Dashboards variant that enriches real-time network telemetry with asset vulnerability data. By matching hostnames over a sliding 5-minute window, this query lets developers build dashboard widgets that visualize asset risk levels. The logic dynamically adjusts a risk score based on network throughput and the highest severity vulnerability found on the asset, providing a prioritized view of potentially compromised systems.
```
$u.udm.principal.hostname = $hostname
$asset_context.graph.entity.hostname = $hostname

$severity = $asset_context.graph.entity.asset.vulnerabilities.severity

match:
  $hostname over 5m

outcome:
  $total_network_bytes = sum($u.network.sent_bytes) + sum($u.network.received_bytes)

  $risk_score = if($total_network_bytes > 1024, 100, 50) +
    max(
      if($severity = "HIGH", 10)
      + if($severity = "MEDIUM", 5)
      + if($severity = "LOW", 1)
    )

  $asset_id_list =
    array(
      if($u.principal.asset_id = "",
        "Empty asset id",
        $u.principal.asset_id
      )
    )

  $asset_id_distinct_list = array_distinct($u.principal.asset_id)

  $asset_id_count = count($u.principal.asset_id)

  $asset_id_distinct_count = count_distinct($u.principal.asset_id)

condition:
  $u and $asset_context and $risk_score > 50 and not arrays.contains($asset_id_list, "id_1234")

```
### Refactor a multi-event `outcome` rule (pre-refactor)
Use case: Improve system performance and reduce processing latency by converting multi-event rules into single-event rules. This is ideal for rules that were originally designed with a match section only to enable the outcome section, but do not actually require correlation across multiple distinct events.
Key logic: Removes the `match` section and any aggregate functions (for example, `max()`, `sum()`, or `count()`) from the `outcome` section. This transition shifts the rule from grouping events over time to evaluating each event individually as it arrives. `match` section), and multi-event rules (rules with a `match` section).
You can use the `outcome` section for both single-event rules (rules without a If you previously designed a rule to be multi-event just so you could use the outcome section, you can optionally refactor those rules by deleting the `match` section to improve performance. Be aware that because your rule no longer has a `match` section that applies grouping, you might receive more detections.
#### Example: Outcome refactor (pre-refactor)
### Rule

The following example shows a multi-event outcome rule that uses only one event variable. Because it uses a `match` section, the Rules Engine must group events over a 5-minute window before calculating the outcome, which consumes more resources than a single-event evaluation. Note: This refactor is only possible for rules that use one event variable.
```
rule OutcomeMultiEventPreRefactor {
meta:
  author = "alice@example.com"
  description = "Outcome refactor rule, before the refactor"

events:
  $u.udm.principal.hostname = $hostname

match:
  $hostname over 5m

outcome:
  $risk_score = max(if($hostname = "my-hostname", 100, 50))

condition:
  $u
}

```
### Search

Stats query equivalent
```
events:
  $u.udm.principal.hostname = $hostname

match:
  $hostname over 5m

outcome:
  $risk_score = max(if($hostname = "my-hostname", 100, 50))

condition:
  $u

```
### Dashboard

```
events:
  $u.udm.principal.hostname = $hostname

match:
  $hostname over 5m

outcome:
  $risk_score = max(if($hostname = "my-hostname", 100, 50))

condition:
  $u

```
### Refactor a multi-event `outcome` rule (post-refactor)
Use case: Finalizing the optimization of a query to improve processing speed. By removing the grouping requirement, the query now triggers a detection immediately upon the arrival of a single matching event, which is significantly more efficient for the Rules Engine.
Key logic: Deletes the `match` section and removes the `aggregate` function (for example, `max()`) from the `outcome` variable assignment. The logic within the if statement remains the same, but is now applied to a single event rather than a group.
You can refactor the query by deleting the `match` section. Note: You must also remove the aggregate in the `outcome` section because the query is now a single-event. For more information on aggregations, see outcome aggregations.
#### Example: Outcome refactor (: #outcome-post-refactor)
### Rule

```
rule OutcomeSingleEventPostRefactor {
meta:
  author = "alice@example.com"
  description = "Outcome refactor rule, after the refactor"

events:
  $u.udm.principal.hostname = $hostname

// We deleted the match section.

outcome:
  // We removed the max() aggregate.
  $risk_score = if($hostname = "my-hostname", 100, 50)

condition:
  $u
}

```
### Search

```
events:
  $u.udm.principal.hostname = $hostname

outcome:
  $risk_score = if($hostname = "my-hostname", 100, 50)

```
### Dashboard

```
events:
  $u.udm.principal.hostname = $hostname

outcome:
  $risk_score = if($hostname = "my-hostname", 100, 50)

```
### Function-to-placeholder assignment
Use case: Normalize data (for example, standardize email domains) to verify grouping in the match section is accurate.
Key logic: Assigns the result of `re.capture()` or `strings.concat()` to a placeholder variable.
#### Example: Function-to-placeholder variable assignment
You can assign a placeholder variable to the result of a function call and can use the placeholder variable in other sections of the rule, such as the `match` section, `outcome` section, or `condition` section.
### Rule

```
rule FunctionToPlaceholderRule {
meta:
  author = "alice@example.com"
  description = "Rule that uses function to placeholder assignments"

events:
  $u.metadata.event_type = "EMAIL_TRANSACTION"

  // Use function-placeholder assignment to extract the
  // address from an email.
  // address@website.com -> address
  $email_to_address_only = re.capture($u.network.email.to , "(.*)@")

  // Use function-placeholder assignment to normalize an email:
  // address@-> address@company.com
  $email_from_normalized = strings.concat(
      re.capture($u.network.email.from , "(.*)@"),
      "@company.com"
  )

  // Use function-placeholder assignment to get the day of the week of the event.
  // 1 = Sunday, 7 = Saturday.
  $dayofweek = timestamp.get_day_of_week($u.metadata.event_timestamp.seconds)

match:
  // Use placeholder (from function-placeholder assignment) in match section.
  // Group by the normalized from email, and expose it in the detection.
  $email_from_normalized over 5m

outcome:
  // Use placeholder (from function-placeholder assignment) in outcome section.
  // Assign more risk if the event happened on weekend.
  $risk_score = max(
      if($dayofweek = 1 or $dayofweek = 7, 10, 0)
  )

condition:
  // Use placeholder (from function-placeholder assignment) in condition section.
  // Match if an email was sent to multiple addresses.
  #email_to_address_only > 1
}

```
### Search
Note: No event variables are required.
```
metadata.event_type = "EMAIL_TRANSACTION"

// Use function-placeholder assignment to extract the
// address from an email.
// address@website.com -> address
$email_to_address_only = re.capture(network.email.from , "(.*)@")

// Use function-placeholder assignment to normalize an email:
// address@??? -> address@company.com
$email_from_normalized = strings.concat(
  re.capture(network.email.to , "(.*)@"),
  "@company.com"
  )

// Use function-placeholder assignment to get the day of the week of the event.
// 1 = Sunday, 7 = Saturday.
$dayofweek = timestamp.get_day_of_week(metadata.event_timestamp.seconds)

match:
  // Use placeholder (from function-placeholder assignment) in match section.
  // Group by the normalized from email, and expose it in the detection.
  $email_from_normalized over 5m

outcome:
  // Use placeholder (from function-placeholder assignment) in outcome section.
  // Assign more risk if the event happened on weekend.
  $risk_score = max(
    if($dayofweek = 1 or $dayofweek = 7, 10, 0)
    )

condition:
  // Use placeholder (from function-placeholder assignment) in condition section.
  // Match if an email was sent to multiple addresses.
  #email_to_address_only > 1

```
### Dashboard

The following example demonstrates a Dashboards variant optimized for time-series visualization. By using a one-day tumbling window, instead of minute-level granularity, this query produces stable, non-overlapping data points ideal for charting risk scores over an extended period. The logic normalizes email entities and applies higher risk weightings to weekend transactions, providing a clear daily trend of suspicious email activity for long-term monitoring.
```
metadata.event_type = "EMAIL_TRANSACTION"

// Use function-placeholder assignment to extract the
// address from an email.
// address@website.com -> address
$email_to_address_only = re.capture(network.email.from , "(.*)@")

// Use function-placeholder assignment to normalize an email:
// address@??? -> address@company.com
$email_from_normalized = strings.concat(
re.capture(network.email.to , "(.*)@"),
"@company.com"
)

// Use function-placeholder assignment to get the day of the week of the event.
// 1 = Sunday, 7 = Saturday.
$dayofweek = timestamp.get_day_of_week(metadata.event_timestamp.seconds)

match:
// Use placeholder (from function-placeholder assignment) in match section.
// Group by the normalized from email, and expose it in the detection.
$email_from_normalized over 5m

outcome:
// Use placeholder (from function-placeholder assignment) in outcome section.
// Assign more risk if the event happened on weekend.
$risk_score = max(
  if($dayofweek = 1 or $dayofweek = 7, 10, 0)
  )

condition:
// Use placeholder (from function-placeholder assignment) in condition section.
// Match if an email was sent to multiple addresses.
#email_to_address_only > 1

```
## Optimization and filtering
Effective rule optimization relies on precise data filtering to ensure the detection engine only processes meaningful information. By excluding "noisy" or incomplete data, you can significantly improve rule performance and make sure that generated alerts are actionable.    Topic Examples     Zero value exclusion Explicit and implicit zero value exclusion
### Zero value exclusion
Use case: Make sure rule accuracy and reduce false positives by explicitly filtering out empty strings, null values, or generic placeholder accounts (for example, "Guest") that don't provide actionable security data.
Key logic: Leverages the Rules Engine's implicit filtering of zero values for variables used in the `match` section, while using explicit inequality operators (`!= ""`) for other event fields to make sure only populated data triggers a detection.
Rules Engine implicitly filters out the zero values for all placeholders that are used in the `match` section. Use the `allow_zero_values` option to disable. However, for other referenced event fields, zero values aren't excluded unless you explicitly specify such conditions. For more information, see Zero values in match section.
#### Example: Explicit and implicit zero value exclusion
### Rule

```
rule ExcludeZeroValues {
meta:
  author = "alice@example.com"

events:
  $e1.metadata.event_type = "NETWORK_DNS"
  $e1.principal.hostname = $hostname

  // $e1.principal.user.userid may be empty string.
  $e1.principal.user.userid != "Guest"

  $e2.metadata.event_type = "NETWORK_HTTP"
  $e2.principal.hostname = $hostname

  // $e2.target.asset_id cannot be empty string as explicitly specified.
  $e2.target.asset_id != ""

match:
  // $hostname cannot be empty string. The rule behaves as if the
  // predicate, `$hostname != ""` was added to the events section, because
  // `$hostname` is used in the match section.
  $hostname over 1h

condition:
  $e1 and $e2
}

```
### Search

You must explicitly state the `hostname` can't be an empty string as there is no implicit zero value filter for placeholders in the `match` section.
```
$e1.metadata.event_type = "NETWORK_DNS"
$e1.principal.hostname = $hostname

// $e1.principal.user.userid may be empty string.
$e1.principal.user.userid != "Guest"

$e2.metadata.event_type = "NETWORK_HTTP"
$e2.principal.hostname = $hostname

// $e2.target.asset_id and hostname cannot be empty string as explicitly specified.
$e2.target.asset_id != ""
$hostname != ""

match:
  $hostname over 1h

```
### Dashboard

You must explicitly state the `hostname` can't be an empty string as there is no implicit zero value filter for placeholders in the `match` section.
```
$e1.metadata.event_type = "NETWORK_DNS"
$e1.principal.hostname = $hostname

// $e1.principal.user.userid may be empty string.
$e1.principal.user.userid != "Guest"

$e2.metadata.event_type = "NETWORK_HTTP"
$e2.principal.hostname = $hostname

// $e2.target.asset_id and hostname cannot be empty string as explicitly specified.
$e2.target.asset_id != ""
$hostname != ""

match:
  $hostname over 1h

```