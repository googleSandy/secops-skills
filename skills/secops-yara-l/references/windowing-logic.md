# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/windowing-logic

# YARA-L 2.0 windowing logic
Supported in:    Google secops   SIEM
This guide helps Security Engineers choose the correct window type for queries to avoid "variable not bounded" compiler errors. Transitioning from sliding windows to tumbling windows lets you build logic that depends on the absence of events, such as a missing heartbeat or a failed log source.
## Before you begin
Confirm your account has one of the following roles to create and modify YARA-L queries:  Detection Engine Admin (`roles/chronicle.detectionEngineAdmin`) SecOps Editor (`roles/chronicle.editor`)
## Supported window types
YARA-L 2.0 uses different windowing behaviors to determine how time is sliced and how events group together. You can group event fields and placeholders in the `match` section by a specified time granularity using the following supported windows:    Supported window type Syntax Description Common use case     Hop `$key over <duration>` Creates fixed, overlapping time intervals. The system defines the overlap and alignment to catch events near boundaries. General correlation of multiple events, regardless of exact start times.   Tumbling `$key by <duration>` Segments data into fixed-size, continuous, non-overlapping blocks. Evaluates independently of event arrival. Quantifying activity in fixed slots (for example, `$user by 30m`) or detecting the absence of events.   Sliding `$key over <duration> [before|after] $pivot` Anchors the window to a specific `"pivot"` event. Requires that pivot to exist to trigger a look back or look forward. Strict sequencing where event order is critical (for example, `File Download after Login`).
## Understand `window_start` and `window_end` logic
Google Security Operations provides two universal, reserved keywords that resolve directly to GoogleSQL timestamps for use within queries. These keywords let you access the boundaries of your time buckets:  `window_start`: The beginning boundary of the time bucket. `window_end`: The closing boundary of the time bucket.
### Usage constraints
Match requirement: You must define a window (`by` or `over`) in the `match` section to use these keywords. Section restriction: Use these keywords in `condition`, `order`, or `outcome`. They're invalid in the `events` section. Namespace: Don't use these as custom variable names (for example, `$window_start`).
### Determine your window type and syntax
Use this table as a quick reference when determining which window type and syntax to use for your detection rules.    Scenario Recommended window Recommended keywords Key advantage     High-frequency detections (for example, brute force attacks) Sliding Window (`over`) `window_start`, `window_end` Triggers immediately as the threshold is met within a rolling period.   Absence/non-existence (for example, missing heartbeats) Tumbling Window (`by`) `window_start`, `window_end` Evaluates fixed time blocks even if zero events occur, preventing Variable Not Bounded errors.   Chronological reporting Sliding or tumbling `order: window_start asc` Standardizes alert output for easier timeline analysis in the Chronicle UI.   Time-bound filtering Sliding or tumbling `condition: window_start > "2026-01-01 00:00:00Z"` Limits rule evaluation to specific dates using GoogleSQL timestamp coercion.
### Compare timestamp types and timezones
YARA-L supports comparing `window_start` and `window_end` directly with strings in GoogleSQL timestamp format. This lets you perform precise filtering without manual type casting.
Note: Always specify UTC using the `Z` suffix (for example, `"2026-03-17T17:35:00Z"`) to align with UDM event timestamps.
Use timestamp filters for performance. If you only need to confirm one event happened after another, a timestamp comparison in the `condition` section is often more efficient: `$e1.metadata.event_timestamp.seconds < $e2.metadata.event_timestamp.seconds`.
Learn more about the `match` section syntax and the `condition` section syntax.
#### Examples: `window_end` and `window_start`
`window_end < "2026-01-01T12:30:00Z"` (date, time, and UTC suffix) `window_start != "2026-01-01 15:00:00+00"` (with UTC offset)
If your comparison fails, verify that your string follows the GoogleSQL canonical timestamp format.
### Hop windows
A hop window creates overlapping time intervals so events happening near the boundaries of a window aren't missed.  Use case: Best for detections where you need to catch a specific scenario regardless of exactly when the window interval starts or ends. Support: Supported for aggregation in Search and Dashboards.
YARA-L queries with a `match` section use hop windows to correlate multiple events over time. The system divides the time range of the query's execution into a set of fixed, overlapping hop windows. While you specify the duration of these windows in the `match` section, the system defines the overlap interval and window alignment. Events then correlate within each of these predetermined windows. Note: Use the hop window unless you require a specific sequence of events (order A then order B). Only use sliding windows when event sequencing is critical or when you search for missing events.
Learn more about the `match` section syntax.
#### Example: Overlapping hop windows for continuous correlation
The following example shows a query run over the time range `[1:00, 2:00]`, with a `match` section `$user over 30m`. A possible set of overlapping hop windows the system generates is `[1:00, 1:30]`, `[1:03, 1:33]`, and `[1:06, 1:36]`.
### Rule

```
rule hop_window_brute_force_example {
meta:
  description = "Detects multiple failed logins within a shifting 30-minute window."
  severity = "Medium"

events:
  $login.metadata.event_type = "USER_LOGIN"
  $login.extensions.auth.auth_status = "FAILURE"
  $login.principal.user.userid = $user

match:
  // This creates the overlapping windows (e.g., 1:00-1:30, 1:03-1:33)
  $user over 30m

condition:
  // This will trigger if 10 or more failures fall into any single 30m hop
  #login >= 10
}

```
### Search

```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
principal.user.userid = $user

match:
  // This creates the overlapping windows (e.g., 1:00-1:30, 1:03-1:33)
  $user over 30m
  ```

```
 
### Dashboard

```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
principal.user.userid = $user

match:
// This creates the overlapping windows (e.g., 1:00-1:30, 1:03-1:33)
$user over 30m

```
  
#### Example: Multi-event correlation using a hop window
 
The following example captures events that occur within the same general timeframe:  
### Rule

```
rule hop_window_example {
meta:
description = "Detect a user with a failed login followed by a success within 30m"

events:
// Event 1: Capture failed login attempts
$fail.metadata.event_type = "USER_LOGIN"
$fail.security_result.action = "FAIL"
$fail.principal.user.userid = $user

// Event 2: Capture successful login attempts
$success.metadata.event_type = "USER_LOGIN"
$success.security_result.action = "ALLOW"
$success.principal.user.userid = $user

match:
// Correlate events for the SAME $user within a rolling 30-minute window.
$user over 30m

condition:
// Ensure both a failed ($fail) and a successful ($success) login event occurred for the same user within the 30m window.
$fail and $success
}

```
 
### Search

```
// Event 1: Capture failed login attempts
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
principal.user.userid = $user // Assign user ID to a placeholder

// Event 2: Capture successful login attempts
metadata.event_type = "USER_LOGIN"
security_result.action = "ALLOW"
principal.user.userid = $user // Link to the same user placeholder

match:
// Correlate events for the SAME $user within a rolling 30-minute window.
$user over 30m

```
 
### Dashboard

```
// Event 1: Capture failed login attempts
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
principal.user.userid = $user // Assign user ID to a placeholder

// Event 2: Capture successful login attempts
metadata.event_type = "USER_LOGIN"
security_result.action = "ALLOW"
principal.user.userid = $user // Link to the same user placeholder

match:
// Correlate events for the SAME $user within a rolling 30-minute window.
$user over 30m

```
  
#### Example: Hop window comparison
 
To identify a brute-force attempt, a `10m` window groups all `USER_LOGIN` failures. The condition then evaluates if the count (`#e`) within that specific 10-minute bucket exceeds your threshold.  
### Rule

```
rule failed_logins
{
meta:
author = "Security Team"
description = "Detects multiple failed user logins within 10-minute windows."
severity = "HIGH"

events:
$e.metadata.event_type = "USER_LOGIN"
$e.security_result.action = "FAIL"
$user = $e.target.user.userid

match:
$user over 10m

condition:
#e >= 5
}

```
 
### Search

```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
$user = target.user.userid

match:
$user over 10m

```
 
### Dashboard

```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
$user = target.user.userid

match:
$user over 10m

```
  
### Tumbling windows
 Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms. 
Note: This feature is not available to all customers in all regions. 
A tumbling window segments data into fixed-size, non-overlapping, and continuous time intervals. Each event's timestamp falls into exactly one window. There is no overlap between tumbling windows. This contrasts with a hop window or a sliding window, which can have overlapping time intervals. 
To implement a tumbling window, use the `by` operator in the `match` section. Tumbling windows divide time into continuous, back-to-back blocks, for example:  `by 1h`: Creates windows for each hour (for example, `[00:00:00-00:59:59]`, `[01:00:00-01:59:59]`). `by 10m`: Creates windows for each 10-minute interval (for example, `[00:00:00-00:09:59]`, `[00:10:00-00:19:59]`).  
#### Common use cases
 
Use tumbling windows when you need to:  Analyze events in distinct, non-overlapping time blocks. Produce only one detection for a given entity (as defined by the match variables) within each fixed time interval, regardless of how many times the event occurs. Count unique entities over fixed periods.  
#### Deduplication behavior
 
A key characteristic of tumbling windows is how the engine handles detections within each window for the same set of match variables:  One detection per window: For a given set of values for the match variables (for example, a specific `$userid`), the engine generates at most one detection for any single tumbling window. First arrival wins: The first events ingested that satisfy the rule conditions for that set of match variables within a specific window triggers the detection. Deduplication: Any subsequent events matching the criteria within that same window instance won't generate additional detections.  
#### Syntax
 
The syntax in the `match` section is: `match: $variable by <duration>`  `$variable` is the placeholder variable that you are matching on. `duration` is a number followed by a time unit: `m` (minute), `h` (hour), `d` (day). Specify a minimum of one minute and a maximum of 72 hours or three days.  
#### Example: Fixed-interval grouping
 
The following rule groups logins by `$userid` within 1-hour non-overlapping windows.  
### Rule

```
rule TumblingWindowExample {
meta:
description = "Example using a 1-hour tumbling window"

events:
$e.metadata.event_type = "USER_LOGIN"
$e.principal.user.userid = $userid

match:
$userid by 1h

condition:
$e
}

```
 
### Search

```
metadata.event_type = "USER_LOGIN"
principal.user.userid = $userid

match:
$userid by 1h

```
 
### Dashboard

```
metadata.event_type = "USER_LOGIN"
principal.user.userid = $userid

match:
$userid by 1h

```
  
#### Example: Detection behavior (user = "Alex")
  Event 1: Alex logs in at 00:30. This falls into the `[00:00:00-00:59:59]` window. The engine generates a detection for Alex for this window. Event 2: Another user, "Taylor", logs in at 00:45. This also falls into `[00:00:00-00:59:59]`, but because the `$userid` is different, the engine generates a separate detection for Taylor. Event 3: Alex logs in again at 00:40. This is still within the `[00:00:00-00:59:59]` window. Because a detection for Alex already exists, this event is deduplicated. No new detection is generated. Event 4: Alex logs in at 01:20. This falls into the next window, `[01:00:00-01:59:59]`. The engine generates a new detection for Alex.  
Even though Event 1 and Event 4 for Alex occurred less than an hour apart, they fall into separate detections because Event 4 crosses the fixed window boundary. 
#### Configure tumbling windows for absence detections
 
To alert on a count of zero and avoid compiler failures, complete the following steps:  Identify the detection goal. Determine if you are searching for high frequency or a lack of activity. Select the `window`keyword. Use `over` for frequency and `by` for absence. Reference window boundaries. Use `window_start` and `window_end` keywords to reference specific boundaries of the time bucket.  
Context: Use `outcome: $ext_window_end = window_end` to include the exact end-time of a missed heartbeat in alert metadata. 
#### Example: Detect a missing heartbeat with metadata
 
Tumbling windows let you alert on a count of zero, which helps you avoid compiler failures when searching for a lack of activity.  
### Rule

```
rule missing_heartbeat_detection {
meta:
description = "Alert when a system fails to check in within a 24h block"

events:
$e.metadata.event_type = "STATUS_UPDATE"
$host = $e.principal.hostname

match:
$host by 24h  // Tumbling window lets you detect zero counts

outcome:
$event_count = count($e.metadata.id)
$missing_window_start = window_start
$missing_window_end = window_end

condition:
$event_count = 0 and window_start > "2026-01-01T12:30:00Z"
}

```
 
### Search

```
metadata.event_type = "STATUS_UPDATE"
$host = principal.hostname

match:
$host by 24h  // Tumbling window lets you detect zero counts

outcome:
$event_count = count(metadata.id)
$missing_window_start = window_start
$missing_window_end = window_end

```
 
### Dashboard

```
metadata.event_type = "STATUS_UPDATE"
$host = principal.hostname

match:
$host by 24h  // Tumbling window lets you detect zero counts

outcome:
$event_count = count(metadata.id)
$missing_window_start = window_start
$missing_window_end = window_end

```
  
### Sliding windows
 
A sliding window is anchored to a specific pivot event and looks either forward (`after`) or backward (`before`). Note: Only available for Rules; not supported in Search or Dashboards. 
#### Common use cases
 
Use sliding windows when event sequencing is critical:  Strict sequencing: Detect an attack chain (for example, `e1` occurs up to two minutes after `e2`). Relative timing: Find an event that occurs within a specific offset of a trigger (for example, a `Network Connection` within 30 seconds of a `Process Start`). Absence detection: Identify when a required "cleanup" or "heartbeat" event fails to occur after a start event.  
#### Syntax
 
`match: <grouping_keys> over <duration> [before|after] <$pivot_event>`    Component Description Example     Grouping keys Common fields used to link events together. `$host`, `$user`   Duration The time offset from the pivot event. `5m`, `1h`, `30s`   Direction Whether the window extends forward or backward. `after`, `before`   Pivot event The event variable that anchors the window. `$proc`, `$alert`    
The following are valid sliding window examples:  `$var1, $var2 over 5m after $e1` `$user over 1h before $e2` `$host, $ip over 1h before $e2`  
#### Requirements and limitations
  Performance: Sliding windows require more processing power than hop windows. Only use them when event order is strictly required (for example, where one event must happen within five minutes after another event). Single-event queries: Don't use sliding windows for single-event logic. Use multiple event variables in the `condition` section instead.  
#### Example: Forward-looking correlation (`after`)
  
### Rule

```
rule sliding_window_after_example {
meta:
description = "Detect a network connection occurring within 1 minute after a suspicious process launch."
severity = "High"

events:
$proc.metadata.event_type = "PROCESS_LAUNCH"
$proc.principal.hostname = $host

$net.metadata.event_type = "NETWORK_HTTP"
$net.principal.hostname = $host

match:
// $proc is the pivot; the 1-minute window starts at the $proc timestamp
$host over 1m after $proc

condition:
$proc and $net
}

```
 
### Search

`after` is unsupported for Search. 
### Dashboard

`after` is unsupported for Dashboards.  
#### Example: Backward-looking correlation (`before`)
 
Use a `"before"` sliding window to investigate activity leading up to a specific alert. This is often used in root-cause analysis to identify what happened immediately preceding a critical detection.  
### Rule

```
rule sliding_window_before_example {
meta:
description = "Identify file modifications occurring in the 5 minutes before a ransomware alert."
severity = "Critical"

events:
$file.metadata.event_type = "FILE_MODIFICATION"
$file.principal.hostname = $host

$alert.metadata.event_type = "ANTIVIRUS_DETECTION"
$alert.metadata.product_name = "Premium_AV"
$alert.principal.hostname = $host

match:
// $alert is the pivot; the 5-minute window ends at the $alert timestamp
$host over 5m before $alert

condition:
$file and $alert
}

```
 
### Search

`before` is unsupported for Search. 
### Dashboard

`before` is unsupported for Dashboards.  
## Troubleshooting
 
Use this section to understand latency, limits, and fixes for common windowing issues in YARA-L. 
### Latency and limits
  
Rules that use tumbling windows (`by`) only trigger at the end of the fixed time block. For example, a rule with `match: $user by 24h` only evaluates once the 24-hour window has fully elapsed. 
Alert latency: Rules that use `by` (tumbling) only trigger after the fixed time block elapses. A `by 24h` rule won't alert mid-window. 
UI mismatch: In Search and Dashboards, the `window_start` keyword refers directly to the `TIME_BUCKET` field. When you filter or group by `window_start`, the column header displays as `TIME_BUCKET` in the UI.This is a known UI display limitation; your logic remains valid.  
### Error remediation
    Error code Description Fix     Variable Not Bounded The rule uses `over` (sliding window) with a `$count = 0` condition. Change the windowing keyword to `by` (tumbling window). Sliding windows require an event to exist to anchor the window, whereas tumbling windows don't.   UI Header Mismatch The user sees `TIME_BUCKET` in the UI instead of `window_start`. No fix required. Filtering and ordering logic still function correctly using the keywords.   Unknown Identifier: `window_start` The keyword is used, but no window is defined in `match`. Add a windowing statement to your `match` section (for example, `$hostname by 1h`).   Invalid usage of `window_start` in events The keyword is referenced in the `events` section. Move the logic to the `condition` or `outcome` section. Window boundaries calculate only after events group in the match phase.    
##