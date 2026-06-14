# Source: https://docs.cloud.google.com/chronicle/docs/investigation/search-and-search-case-history

# Search cases and case history
Supported in:    Google secops
This guide is for security analysts who want to analyze security telemetry, including Unified Data Model (UDM) events, entities, cases, and case history. It explains how to leverage SIEM Search within Google Security Operations to seamlessly correlate case details with other security data. By following this method, workflows are streamlined, reducing context switching between different interfaces. Successful completion accelerates incident response.
## Common use cases
This section lists common use cases of SIEM Search.
### Triage and case prioritization
Efficiently identify and prioritize security cases based on status, activity, or associated alerts. Value: Enables security teams to focus on the most critical incidents quickly, improving response efficiency.
### Investigate an entity's timeline
Correlate case data with other security telemetry like UDM events and entities to build a comprehensive timeline of an incident. Value: Provides deeper insights into security events, facilitating thorough investigations and better-informed decisions.
## Key terminology
SIEM: Security Information and Event Management. Refers to tools and processes for collecting and analyzing security data from various sources to detect threats. SOAR: Security Orchestration, Automation, and Response. Refers to technologies that help security teams automate, consolidate, and streamline security operations. UDM (Unified Data Model): A standardized data format used within Google SecOps to represent security events from various sources consistently. Case Viewer: A feature within SIEM Search results that allows opening a detailed view of a selected case. Column Manager: A tool to customize the columns displayed in the search results table. Aggregation Panel: Provides summaries and distributions of field values from the search results.
## Query cases and case history
This section provides examples of how to construct queries for cases and case history in SIEM Search.
### Formulate basic case queries
Action/Goal: Find all open cases. Query: `case.status = "OPENED"` Anticipated failure: Incorrect syntax or no matching open cases. Corrective step: Double-check the query syntax and ensure there are indeed open cases in the system.
### Search by specific activity type
Action/Goal: Find cases that include a "CASE_ALERT_DATA" wall activity. Query: `case.wall_activities.activity_type = "CASE_ALERT_DATA"` Anticipated failure: No results if no cases have this activity type, or if the field name is incorrect. Corrective step: Verify the activity type and field name against case documentation.
### Correlate cases with alert and entity data
Action/Goal: Identify cases linked to alerts that have both metadata IDs and associated entity names. Query: `case.alerts.metadata.id != "" AND case.alerts.entities.name != ""` Anticipated failure: The query might be too restrictive, yielding no results. Corrective step: Test parts of the query separately (for example, `case.alerts.metadata.id != ""`) to isolate the issue.
### Query case history for priority changes
Action/Goal: Find historical entries showing a priority change for a case where an assignee is recorded. Query: `case_history.case_activity = "PRIORITY_CHANGE" AND case_history.assignee.name != ""` Anticipated failure: No matching history entries or incorrect field usage. Corrective step: Confirm the exact field names and activity types used in case history.
## Examples information
The following examples demonstrate various search possibilities, including additional queries, statistical analysis, and exporting data to data tables.
### Additional example queries
Find cases based on assignee login time: `case.assignee.last_login_time.seconds = 1778696064 AND case.assignee.last_login_time.nanos = 732156760 AND case.assignee.deleted = false` Find case history entries with informational priority: `case_history.priority = "PRIORITY_INFO"` Find case history events that are not incidents and occurred at a specific time: `case_history.incident = false AND case_history.event_time.seconds = 1778749665 AND case_history.event_time.nanos = 664842769`
### Statistical queries
Case count:  Query: `case.display_name != ""` Outcome: `$case_count = count(case.display_name)`  Case history count:  Query: `case_history.name != ""` Outcome: `$case_count = count(case_history.name)`
### Export to DT queries
You can export search results from cases and case history to data tables for further analysis.  Exporting case data:  Query: `case.name != ""` Outcome & Export: `outcome: $x = case.name export: %new_case_table.write_row( testing: $x )`  Exporting case history data:  Query: `case_history.name != ""` Outcome & Export: `outcome: $x = case_history.name export: %new_case_history_table.write_row( testing: $x )`
### Limitations
The following limitations apply to searching cases and case history within the Google SecOps Search interface:  Alerts, Wall Activities, and Tasks are visible only after pivoting to the case page from case search results and are not available directly in the search view. Active management tasks (for example, modifying case attributes like stage, priority, importance, incident status; editing assignees; adding tasks; or closing cases) are not supported within the Search interface. Case and case history data is read-only within Search. Creation and editing of cases remain in the case module. Cross-resource joins (for example, joining case and case history to show a historical snapshot of a case) or joins within the same resource type (for example, multiple case records) are not supported. Prevalence and activity heatmaps are not available for case or case history searches. No direct Case Lookup functionality is provided. Custom fields are not supported in case or case history searches.
### Programmatic API support
The Programmatic API for Search on cases and case history aligns with the structure and workflow of the existing Asynchronous Search API. Refer to the Search API documentation for details on using the API.
## Troubleshooting
This section outlines performance expectations and provides self-service fixes for common issues encountered when searching cases and case history.
### Error remediation
Specific error codes related to cases and case history searches are not detailed in the provided text. If you encounter errors, ensure your queries adhere to the supported syntax and limitations outlined previously.    Issue Description Fix     Query returns no results Double-check query syntax, field names, and filters. Verify data exists matching your criteria.   Attempting to modify case data Case and case history searches are read-only. Use the dedicated Case module for making modifications.   Attempting to join different resources Cross-resource joins are not supported. Query `case` and `case_history` separately.
### Validation and testing
To validate the success of your queries:  Review Search Results: Examine the table of results to ensure they match your expectations based on the query. Use Built-in Features: Utilize features like Column Manager to display relevant fields and the Aggregation Panel to understand data distributions, helping confirm the query's accuracy. Export and Verify: Use the CSV Download to export results and perform external validation or analysis if needed.