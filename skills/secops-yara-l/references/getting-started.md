# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/getting-started

# Get Started: YARA-L 2.0 in SecOps
Supported in:    Google secops   SIEM
YARA-L 2.0 is the unique, highly structured query language powering Google Security Operations for all search, dashboards, and rule-based threat detection. This document helps you understand the core YARA-L structure and provides practical steps for using it, whether you're a Security Analyst hunting for threats or a Detection Engineer building robust new logic.
This document explains YARA-L and its syntax, showing how you can use it to express everything from a basic filter query to a rule that looks for complex patterns. Use the sections in a YARA-L query to support aggregated functions, condition logic, and add context through joins, pattern matching, and more.
## Before you begin
Verify that you have access to the Google SecOps platform. Verify data ingestion using test rules. You must have a basic understanding of security concepts and log data. This document assumes that data is being ingested into your Google SecOps instance, and normalized to the Unified Data Model (UDM). To jumpstart your query migration, see the Transition from SPL to YARA-L 2.0 guide, which translates common SPL commands like `stats`, `eval`, and `lookup` into YARA-L `outcomes` and `match`conditions.
## Understand the YARA-L structure
Every YARA-L query is segmented into distinct, named sections, which dictate the query's behavior.
This structure is what enables multistage analysis and correlation.    Order Section Rules Search/Dashboards Description     1 `meta` Required Optional Sets descriptive metadata for the rule, such as author, description, and severity. For example, author (`security team`), description (`Detects multiple failed user logins within 10-minute windows`), and severity (`High`).See `meta` section syntax.   2 `events` Required Required Defines and filters the events that must be tracked: user logins, failed user logins (event variables), and links to the user match variable (placeholder variables). Declares all data sources (primarily events) to consider and filters them using UDM fields. See `events` section syntax.   3 `match` Required Optional Groups by events and lets you specify the supported time window (for example, `by 5m`). Required in some cases for statistical searches where aggregation occurs. Required for multi-event correlation queries. Time specification is required in the `match` for rules and optional for search and dashboards. See `match` section syntax.Note: If you exclude a `match` section, the rule can match against a single event.   4 `outcome` Optional Optional Calculates essential metrics and gets insights (for example, `count()`, `avg()`). See `outcome` section syntax.   5 `condition` Required Optional Defines the logic that must be met to either return results (in search) or trigger an alert (in a rule). Evaluates the query variable criteria to determine if a result applies (for example, `$event >5`). See `condition` section syntax.   6 `options` Optional Optional Allows enabling or disabling specific rule behavior. See `options` section syntax.   7 `dedup` N/A Optional Removes duplicate events by grouping them based on key variables or event paths (for example, `target.user.userid`, `target.ip`, `principal.hostname` or variables, such as `$host`, `$user`). Learn more about event variables and how to use deduplication in Search and Dashboards.   8 `order` N/A Optional Sorts results defined by specific fields (for example, `asc`). Learn more about event variables. Optional (only applicable when `match` is used).   9 `limit` N/A Optional Restricts the maximum number of returned events from the query.   10 `select` N/A Optional Specifies the list of UDM fields to include in the query results.   11 `unselect` N/A Optional Specifies the list of UDM fields to exclude from the query results.
### YARA-L data source availability
YARA-L has access to different data sources, depending on where you are in the platform. Events, entities (ECG), and data tables are fully available across search, dashboards, and rules. For details about sample queries, see Data sources supported.
The following table lists the available features in YARA-L:    Feature Available In     Cases and case history Dashboards   Data tables Search, dashboards, rules   Entities (ECG) Search, dashboards, rules   Ingestion metrics Dashboards   IoC matches Dashboards   Rule detections Dashboards, rules   Rule sets Dashboards   Events Search, dashboards, rules   UEBA metrics Search, dashboards
## Build your first YARA-L search
All data in Google SecOps is searched using two primary methods based on your goals: filter search and statistical search (aggregations).
### Filter search (event filtering)
The filter search method lets you isolate specific events from the broader telemetry stream without the overhead of statistical aggregation. This method uses criteria to narrow down massive volumes of security data—such as logs or network traffic—into a targeted result set. The logic only requires you to specify events in the `events` section.
To build your first YARA-L filter search, follow these steps to search for users with failed logins:  In Google SecOps, go to the search page.  Filter for login events: `metadata.event_type = "USER_LOGIN"`
Tip: You can omit the `events:` section header in your searches. By default, the search syntax implies this section.  Add `event` actions for failed logins from users who don't have an empty `userid`.
```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
principal.user.userid != ""
```
Run this search to see the results.
### Use placeholder variables
Use placeholder variables to extract specific values from your events, such as a username or an IP address. These variables act as temporary anchors that let you compare data across different events or display those values in your final output.
You apply placeholder variables to do the following:  Bridge data: Use placeholders, such as `$userid` or `$ip` to find matches between different event variables (for example, you can use `$userid` to link the user identifier across the login and logout events). Group results: In the `match` section, use placeholder variables to define the window of your query output, such as `match: $userid over 1h`. Create outcomes: Use placeholders to capture and display specific data points in your query output.
For example, if you assign `$user = principal.user.userid`, the `$user` variable now holds the specific value extracted from the event. You then use `$user` in the `match` section to group all activity related to that specific user.
### Statistical search (aggregation)
The statistical search method helps you get insights, trends, or anomalies by performing calculations across sets of events. Instead of returning a list of individual logs, it provides aggregated summaries of your data. The logic uses the `match` section (for grouping) and the `outcome` section (for calculations). The `outcome` section supports aggregation functions, such as `count()`, `sum()`, `avg()`, `max()`, `min()`, and `stddev()`.
The following example uses the following query logic:  `events`: Filters the raw data for failed login attempts. `match`: Defines the grouping events (by `userid`). `outcome`: Performs the statistical aggregation (event count per user).
#### Example: Aggregate failed login activity using `outcome` functions
The following example uses the `outcome` section's aggregation functions (like `count()` or `sum()`) to summarize failed login activity.
Use the `match` section to group the failed login events by `userid`:
```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
principal.user.userid != ""

match:
  principal.user.userid

```
Use the `count` of failed logins for each user (`$failed_login_count`), defined by the `outcome` variable:
```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
principal.user.userid != ""

match:
  principal.$user.userid

outcome:
  $failed_login_count = count(metadata.id)

```
Run this search to see the results.
Optional: Add an element of time to the `match` section (in this case, `day`). Then, update the `outcome` variable to be more explicit (`$daily_failed_login_count`):
```
metadata.event_type = "USER_LOGIN"
security_result.action = "FAIL"
principal.user.userid != ""
$user = principal.user.userid

match:
  $user by day

outcome:
  $daily_failed_login_count = count(metadata.id)

```
Note: You create a tumbling window when you apply the `by` operator to your grouping logic.
## Create a dashboard widget from your search
You can create a dashboard widget from aggregated searches, such as shown in the build your first search example. Note: The ability to visualize in search is only enabled for a statistical search.
Once the search is validated, you can save it as a widget and add it to your dashboard, as follows:  When you see the results, click the Visualize tab > Add to Dashboard. Configure the widget:  Name the widget (for example, `"Daily Failed Login"`). Select a time range. Choose whether to add it to an existing or new dashboard. Click Add.   Optional: Build queries directly into your dashboards. Alternatively, you can copy curated dashboards and modify edits to queries within them as a starting point. Optional: You can make a custom dashboard and add widgets to that using YARA-L. For details, see Create a custom dashboard.
### Configure a dashboard
When you build a new dashboard, the `events` section is a required starting point. From there, you have the flexibility to use `match` (for grouping results) or `outcome` (for calculating outputs and aggregations).
For example, you can have a dashboard with `events` and `match` sections, where your dashboard shows the severity (`$severity`) of detections grouped `by hour` buckets.
#### Example: Aggregate time-series by severity
You can create a dashboard using the `events` and `match` sections to display the severity (`$severity`) of detections grouped into `hour` buckets:
```
detection.detection.severity != "UNKNOWN_SEVERITY"
$severity = detection.detection.severity

match:
  $severity by hour

```
#### Example: Aggregate total critical impact
Similarly, you can create a dashboard using the `events` and `outcome` sections to track high-severity detections:
```
detection.detection.severity = "CRITICAL"
$severity = detection.detection.severity

outcome:
  $detection_count = count_distinct($severity)

```
#### Example: Visualize detection volume by severity over time
In the following example, you can count critical detections and specify the time range through the console. In many cases, you will use both the `match` and `outcome` sections when building a visualization in a dashboard:
```
detection.detection.severity != "UNKNOWN_SEVERITY"
$severity = detection.detection.severity

match:
  $severity by hour

outcome:
  $detection_count = count_distinct(detection.id)

```
#### Example: Calculate user login frequency
The following example focuses on calculating the `login_count` for specific users using the `match` and `outcome` sections:
```
events:
  metadata.event_type = "USER_LOGIN"

match:
  target.user.userid

outcome:
  $login_count = count(metadata.id)

```
## Build a rule
A rule requires the following sections:  `meta`: Contains the rule name and descriptive details. `events`: Defines your data sources and filters using event variables. `condition`: Specifies which event variables must exist for the rule to trigger.
### Define and use event variables
Event variables act as a logical container, grouping your filters together so you can reference that specific activity throughout your search, rule or dashboard.
When you define logic in the `events` section, you can use event variables (such as `$e`) to represent a specific event (or a group of events) that match your criteria.
#### Example: Define and filter event variables
To define an event variable (for example, `$e`), use a prefix in the `events` section of your query. This declares those events to be represented by the variable. For instance, the expression `$e.principal.hostname = "dev"` evaluates each event to determine if the hostname is an exact match.
```
$e.principal.hostname = "dev"
$e.metadata.event_type = "USER_LOGIN"

```
You can then use that variable in other sections of the query to reference that specific group of events (in `match`, `outcome`, `condition` sections) and their data fields. Note: You can use event variables in rules, but they're optional in search and dashboards, depending on the query. See the multi-event correlation example.
### Organize rule structure and syntax
Use the following rule structure and syntax to help you define your variables, grouping logic, and trigger thresholds:    Element Description Example     Rule structure Wraps your query in a `rule` block and assigns a unique name to identify the detection. `rule DailyFailedLoginAttempts { }`   `meta` section Required. Includes descriptive metadata (such as `author`, `description`, `severity`) to improve rule management and provide context for your team. Recommended as a best practice for rule management.  `author = "Alex"``severity = "Medium"`   Event variable In a rules query, each field in the `events` section is prefixed with an event variable (like `$e`) to represent a specific event (or a group of events) that match your criteria. They act as logical groupings of filters. In the Convert your search to a YARA-L rule example, `$e` represents all user failed logins. `$e.metadata.event_type = "USER_LOGIN"`   Placeholder variable Assigns an event to a common name that you can reference later in the query. For details, see Use placeholder variables. `$userid = $e.principal.user.userid`   `match` section Defines your groupings and specifies a supported time window. In the Convert your search to a YARA-L rule example, the `match: $userid over day` grouping correctly groups events by the user ID within each 24-hour period (`1d`). When you write a rule, you must specify a supported time window to define your lookback period. You can implement a hop, sliding, or tumbling window depending on your logic requirements. Using the `over` operator explicitly creates a hop window.  `$userid over 1d`   `outcome` section Performs statistical aggregations or captures specific variables to make your resulting alerts more informative. Use the `count()` function on `$e.metadata.id` to aggregate events within each `match` group. You can also assign variables, such as `$userid`, to capture specific UDM fields and provide more context in the resulting detection output. `$failed_count = count($e.metadata.id)`   `condition` section Required for a rule to generate a detection. Defines your detection threshold in the `condition` section. For example, using `#e > 5` requires that the event count must exceed five (`5`) to trigger an alert. If you're not performing calculations, you still need a `condition` section and state the existence of the event variable (for example, `#e`). Analyze your environment's baseline to set thresholds that catch suspicious activity while minimizing false positives. If you’re not performing calculations, you still need a `condition` section and simply state the existence of the event variable, such as `#e`. `#e > 5` or `$e`
To understand how this structure works, see the following example.
#### Example: Detect brute force (multiple failed logins)
The following example detects multiple failed login attempts for a single user within a 24-hour window:
```
rule DailyFailedLoginAttempts {
  meta:
    author = "Alex"
    description = "Detects multiple failed login attempts for a single user within a day."
    severity = "Medium"

  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "FAIL"
    $e.principal.user.userid != ""
    $userid = $e.principal.user.userid

  match:
    $userid over 1d

  outcome:
    $daily_failed_login_count = count($e.metadata.id)

  condition:
    $daily_failed_login_count > 5
}

```
Note: To test this rule, use the Test Rule feature in the Rules Editor against historical data to confirm it works as expected. For details, see how to run a rule against historical data.
## Convert your search to a YARA-L rule
Note: This process helps highlight some of the key differences between query requirements in search or dashboards and rules.
To convert a finalized search query into a reliable rule for generating detections, you typically follow these steps:  In Google SecOps, go to the Rules Editor. Start a new rule. Paste the search query and modify it to fit the rule structure, including:  `meta` section: Defines the metadata rule, including the rule name, author, and severity level `event` section: Required. Unlike in search, you must have a named `event``` section header. Event variables: Declares and references specific events (or groups of events) within your logic. `match` section with supported time windows: Specifies your grouping keys and defines the time parameters (for example, `5m` or `1d`). Note: If you use a `match` section in rules, you must add a time window. `condition` section: Defines the final logic or threshold that must be met to trigger a rule.   
## Advanced: Build a multi-event rule
 
You use a multi-event rule to correlate different types of activity that occur within a specific timeframe. Instead of looking at a single event, you connect multiple events, such as a user logging in and then immediately performing an unusual file download, to identify complex threats. 
A multi-event rule requires the following sections:  `meta`: Contains the rule name and descriptive details. `events`: Defines your data sources and filters using event variables. `match`: Sets the timeframe and the placeholder variable used to bridge your events. `outcome`Captures additional context for the alert. Multi-event rules require an aggregation function. `condition`: Specifies which event variables must exist for the rule to trigger.  
To build a multi-event rule, do the following:  Define your event variables: In the events section, define `$e1` to capture `"PROCESS_LAUNCH"` events and `$e2` to capture specific malicious file hashes. Correlate with placeholders: Use the `$user` placeholder variable to connect these two distinct event streams by a shared principal user ID (for example, `$user = $e1.principal.user.userid and $user = $e2.principal.user.userid`). Group the match: In the `match` section, you specify that these events must happen for the same `$user` within a set window of time, such as 5 minutes (`5m`).  
#### Example: Build a multi-event rule
 
In the following example, `$e1` represents a `PROCESS_LAUNCH` event and `$e2` represents an event with a specific malicious hash. The `$user` placeholder variable correlates these events by the same principal user ID. 
```
rule MultiEventExample {
meta:
author = "Alex"
description = "Detects a bad hash execution or a process launch from a specific IP for the same user."

events:
$e1.principal.ip = "1.1.1.1"
$e1.metadata.event_type = "PROCESS_LAUNCH"
$e2.target.file.sha256 = "badhash..."
$user = $e1.principal.user.userid
$user = $e2.principal.user.userid

match:
$user over 5m

condition:
$e1 or $e2
}

```
 
The following rule components describe the logic used in the example:  Event variables: Defined two event variables, `$e1` and `$e2`. Used the placeholder variable `$user` to join these events on the common `userid` field. `match` section: Included a `match` section for this multi-event rule to group by user and specify a hop time window of five minutes (`5m`) to correlate the events. `condition` section: Defined the logic to trigger the alert. This example triggers an alert if either the first or the second event exists.  Note: You can use the Test Rule function in the Rules Editor to validate this query. For details, see Run a rule against historical data. 
## Use other tools to build your query
 
These tools are essential companions for writing, validating, and accelerating YARA-L adoption:  UDM Lookup tool: Quickly search and reference UDM field names, definitions, and data types directly within the UI. If the field ID is unknown, prioritize checking this reference. Natural language to YARA-L search: In the search bar, enter descriptions to draft your initial query or get or translate corresponding YARA-L suggestions. SPL → YARA-L Translator (Labs tool): If you're transitioning from competitor platforms, use this tool (available in the Labs section) to convert legacy Splunk SPL queries into YARA-L. This generates a structured starting point, which accelerates your migration and refines your detection logic. To use the Labs tool, in Google SecOps, go to yourinstancename.chronicle.security/labs.  
##