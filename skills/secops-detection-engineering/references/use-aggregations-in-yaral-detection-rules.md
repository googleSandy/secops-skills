# Source: https://docs.cloud.google.com/chronicle/docs/investigation/use-aggregations-in-yaral-detection-rules

# Use aggregations in YARA-L queries
Supported in:    Google secops   SIEM
This guide helps Security Engineers calculate averages or totals within a YARA-L query. It explains how to use the required syntax to prevent compiler errors.
## Common use cases
The following scenarios represent the primary objectives for using aggregations within YARA-L.
### Detect volume-based anomalies
Objective: Identify when a specific metric, such as data exfiltration or login attempts, exceeds a historical baseline. Value: Automated thresholding reduces manual tuning and lets you catch stealthy, low-and-slow attacks that static limits might miss.
### Triage and prioritize cases
Objective: Calculate risk scores in the `outcome` section based on the deviation from a calculated average. Value: Analysts can focus on detections with the highest statistical significance, which improves response times and reduces alert fatigue.
## Key terminology
Understanding the following platform-specific terms is essential for writing valid YARA-L 2.0 syntax:  `window. prefix`: A syntax requirement for specific aggregation functions in the Rules engine. It instructs the platform to perform a calculation across the entire `match` window, rather than on a single event. `outcome` section: The portion of a YARA-L rule you use to compute variables and provide additional context for the resulting detection. Learn more about the `outcome` section syntax. `match` window: The specific duration of time (for example, `7d`) defined in the `match` section that the engine uses to group events. Learn more about the `match` section syntax.
## Before you begin
Verify that you have the following access and understanding of requirements before you create windowed aggregations:  Permissions: You must have the Detection Author (`roles/chronicle.detectionAuthor`) IAM role to access the Rules Editor.
## Implement aggregations in the `outcome` section
To correctly aggregate data for threshold-based alerts, follow these steps:  Define the outcome variable. Create a variable in the `outcome` section to hold your calculated value.
Apply the `window.` prefix. The following functions require the `window.` prefix to explicitly bound the calculation to the `match` window. Note: In UDM Search or Dashboards and basic aggregations (such as `max`, `min`, `sum`, and `count`) don't require the `window.` prefix. However, more complex statistical or ordering functions do require it.    Category Supported windowed functions     Statistical `window.avg`, `window.variance`, `window.variance_pop`, `window.percentile`, `window.mode`, `window.stddev`   Ordering `window.first`, `window.last`, `window.last_non_null`
Required syntax: `$avg_bytes = window.avg($e.network.sent_bytes)`
Set the threshold condition. Compare your real-time events against the `outcome` variable in the `condition` section.
#### Example: Detect significant network spikes
Use the following example to implement a "3x average" (`3 * $avg_bytes`) detection logic.
### Rule

```
rule NetworkBytesSpikeDetection {
meta:
  author = ""
  description = "Detects when network sent bytes significantly spike above the average for a host."
  severity = "Medium"

events:
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.principal.hostname = $hostname
  $e.network.sent_bytes > 0

match:
  // Define the window over which aggregations in the outcome section are calculated.
  $hostname over 1h

outcome:
  // Calculate the maximum value of network.sent_bytes within the 1h window.
  $max_sent_bytes = max($e.network.sent_bytes)
  $avg_sent_bytes = window.avg($e.network.sent_bytes)
  // Calculate the threshold: 3 times the average sent bytes.
  $threshold = 3 * $avg_sent_bytes

condition:
  // The rule triggers if there is at least one matching event ($e)
  // AND the maximum sent bytes ($max_sent_bytes) exceeds the calculated threshold.
  $e and $max_sent_bytes > $threshold
}

```
### Search

```
metadata.event_type = "NETWORK_CONNECTION"
principal.hostname = $hostname
network.sent_bytes > 0

match:
  // Define the window over which aggregations in the outcome section are calculated.
  $hostname over 1h

outcome:
  // Calculate the maximum value of network.sent_bytes within the 1h window.
  $max_sent_bytes = max(network.sent_bytes)
  // window.avg is not required in search and dashboard
  $avg_sent_bytes = avg(network.sent_bytes)
  // Calculate the threshold: 3 times the average sent bytes.
  $threshold = 3 * $avg_sent_bytes

```
### Dashboard

```
metadata.event_type = "NETWORK_CONNECTION"
principal.hostname = $hostname
network.sent_bytes > 0

match:
  // Define the window over which aggregations in the outcome section are calculated.
  $hostname over 1h

outcome:
  // Calculate the maximum value of network.sent_bytes within the 1h window.
  $max_sent_bytes = max(network.sent_bytes)
  // window.avg is not required in search and dashboard
  $avg_sent_bytes = avg(network.sent_bytes)
  // Calculate the threshold: 3 times the average sent bytes.
  $threshold = 3 * $avg_sent_bytes

```
## Troubleshooting
This section manages performance expectations and provides self-service fixes for common aggregation issues.
### Validation and testing
Use the Test Rule tool to verify your aggregation logic. Because windowed functions rely on the `match` window, you should inspect the Detection details in the test results.  Verify variable population: Confirm that `$threshold`, `$avg_bytes`, and other `outcome` variables are not `null`. A `null` value usually indicates that the UDM fields referenced in the aggregation are missing from the event data within the selected time range. Inspect numeric accuracy: Confirm that the calculated averages align with your expectations. If the values don't align, check if your `match` window captures the correct volume of telemetry.
### Error remediation
Use the following table to resolve common aggregation and compiler issues when building YARA-L rules.    Error Description Fix     Rule fails to trigger The threshold in your `condition` section is too high or the `outcome` variable returns a `null` value. Use the Test Rule tool to inspect detection details. If results are `null`, verify the UDM fields exist in the telemetry for that window.   High detection latency Calculations are over a large `match` window or high-volume source. Shorten the `match` window or add specific filters in the `events` section.