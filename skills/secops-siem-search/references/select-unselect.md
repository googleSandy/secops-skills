# Source: https://docs.cloud.google.com/chronicle/docs/investigation/select-unselect

# Control columns with select and unselect keywords
Supported in:    Google secops   SIEM
In Search and Dashboards, you can use the `select` and `unselect` keywords to customize the columns displayed in the Events table on the Results tab (in Search) and the tables within dashboard widgets.
While the Timestamp and Event columns display by default, the `select` and `unselect` keywords let you add or remove specific Unified Data Model (UDM) fields, `outcome` variables, or `match` variables to refine your view.
The `select` and `unselect` keywords are optional and are not available in Rules.  `select`: Specifies the list of UDM fields, `outcome` variables, or `match` variables to include in the query results. `unselect`: Specifies the list of UDM fields or variables to exclude from the query results.  Note: These keywords only alter how data is displayed; they don't change the underlying search logic.
## Usage examples
The examples in this section demonstrate common syntax for using the `select` and `unselect` keywords in Search queries.
#### Example: Single event search
The following query searches for events connected to `alex-laptop` and adds `security_result.about.email` as a column to the Events table:
```
principal.hostname = "alex-laptop"
limit: 10
select: security_result.about.email

```
#### Example: Multiple columns
You can add multiple columns by separating them with a comma. The columns appear in the order you list them.
```
principal.hostname = "alex-laptop"
limit: 10
select: network.sent_bytes, security_result.about.email

```
#### Example: Table definitions
In Dashboards, the `table` keyword defines the column output, while `select` or `unselect` manages the specific fields displayed.
```
metadata.event_type = "USER_LOGIN"
select:
  principal.hostname

```
## Aggregation and statistical queries
In YARA-L, you typically place aggregation and statistical functions in the `outcome` section, while the `match` section defines the aggregation base.
The `select` and `unselect` sections are mutually exclusive and let users include or exclude outcome variables, match variables, event fields, or entity fields.
All UDM searches are either single event searches or aggregated searches (also known as event statistics). Aggregate searches specify the `match` keyword or use aggregate functions in the output (for example, `sum` or `count`).
### Aggregated search
The `stats` command is the primary tool for data aggregation. It transforms raw event data into summarized security metrics. While the `eval` command handles field-level, row-by-row transformations, stats performs set-level aggregation (similar to `GROUP BY` in SQL).
#### Example: Aggregated search
The following query excludes the `$count_hostname` variable from the final display to focus on the `$count_id metric`.
```
events:
  $e.metadata.event_type != "RESOURCE_CREATION"
  $e.principal.hostname = $hostname
  $id = $e.network.session_id

match:
  $hostname over 1h

outcome:
  $count_hostname = count($hostname)
  $count_id = count($id)

unselect:
  $count_hostname

```
#### Example: Outcome variables in Search
You can also use a variable with the `select` keyword to display a specific calculation. The following example declares `$seconds` as an outcome variable. The `Events` table then displays the `$seconds` value as a column.
```
principal.hostname = "alex-laptop"

outcome:
  $seconds = metadata.event_timestamp.seconds

limit: 10

select: $seconds, security_result.about.email

```