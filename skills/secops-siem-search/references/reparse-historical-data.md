# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/reparse-historical-data

# Re-parse historical data (Log Replay)
Supported in:    Google secops   SIEM
This guide is for security engineers and detection engineers who want to re-parse historical log data in Google Security Operations using Log Replay. It explains how to validate an active parser configuration and request a backend Log Replay task through Google Cloud Support to backfill updated Unified Data Model (UDM) field mappings across up to 180 days of historical telemetry. By following this method, you can apply updated prebuilt parsers, custom parsers, or parser extensions to stored raw logs when new mapping instructions otherwise apply forward to newly ingested logs only. Successful completion improves historical threat hunting and detection rule coverage without requiring manual log re-ingestion from source endpoints.
## Common use cases
Re-parsing historical logs addresses the following operational scenarios:
### Retroactive field normalization
Objective: Backfill newly mapped UDM fields across historical logs after you activate a prebuilt parser update, custom parser, or parser extension. Value: Maintains consistent searchability across historical and live data without requiring manual re-ingestion from source endpoints.
### Threat hunting in Logs Explorer
Objective: Query historical logs using newly mapped UDM attributes to investigate past adversary activity. Value: Accelerates incident response by surfacing historical indicators of compromise (IOCs) that were previously unmapped in raw log text.
### Historical detection rule evaluation
Objective: Evaluate YARA-L detection rules against past log data that requires specific normalized UDM fields. Value: Prevents false negatives when evaluating updated detection logic against historical events.
## Key terminology
Log Replay: The backend service in Google SecOps that re-processes stored raw logs through an active parser configuration to generate updated UDM records. Unified Data Model (UDM): The standardized schema used by Google SecOps to normalize security telemetry for search, dashboards, and detection rules. Immutable raw repository: The underlying storage layer that retains original, unmodified raw logs for compliance, audit, and historical re-parsing.
## Before you begin
Before you request a Log Replay task, confirm that you meet the following requirements:
Permissions: You must have the following permissions:  View and manage parser configurations in Google SecOps (such as the Chronicle API Editor role). Create support cases in the Google Cloud console (such as the Tech Support Editor role, `roles/cloudsupport.techSupportEditor`).
Environment check: Confirm that you have your Google SecOps customer instance ID and associated Google Cloud project ID.
### Limitations
Log Replay operates within the following supportability boundaries:  Supported retention window: You can request historical re-parsing for up to 180 days (6 months) of historical log data. Active parser required: Log Replay applies the active parser version only. You can't use draft, inactive, or archived parser configurations. Scope specification: Re-parsing is scoped to specific log types and defined start and end timestamps in RFC 3339 UTC format. Immutable raw storage: Log Replay regenerates normalized UDM records only. Original raw logs remain unchanged in the immutable raw repository.
## Request a Log Replay task
Complete the following steps to validate your parser and submit a Log Replay request.
### Validate the active parser configuration
Confirm that the target parser or parser extension is active and normalizing live telemetry before requesting historical re-parsing.  In the Google SecOps console, go to SIEM Settings > Parsers.
Locate your target log type and verify that the updated prebuilt parser, custom parser, or parser extension has an Active status and normalizes live incoming logs as expected. Note: If you submit a replay request while the target parser or extension is still in Draft or Pending status, Google Cloud Support can't execute the replay against the updated mappings. Activate the parser and verify live UDM output first.
### Submit the support case
Submit a support ticket with the required scope parameters so Google Cloud Support can initiate the backend replay job.  Open a support case using the Google Cloud console.
In the support case description, include the following details:  Instance identifier: Your Google SecOps customer instance ID and associated Google Cloud project ID. Log type: The specific `log_type` label to re-parse (for example, `PAN_FIREWALL` or `<var>CUSTOM_LOG_TYPE</var>`). Target time window: The precise start and end timestamps in RFC 3339 UTC format (for example, `2026-06-01T00:00:00Z` to `2026-08-31T23:59:59Z`), within the supported 180-day limit. Parser details: The active parser version, custom parser name, or parser extension ID to apply (Log Replay applies the active version only). Business justification: A brief summary of the requirement, such as retroactive field normalization or incident investigation.  Note: Google SecOps Support reviews each request and rejects submissions that don't include a valid business justification or that exceed the 180-day retention window. Verify that your start and end timestamps fall within the last 180 days and include a clear operational reason before submitting the case.
## Examples and reference information
Use the template in this section to prepare your support request.
### Support case request template
Copy and populate the following template when submitting your support case description:
```
Request type: Google SecOps Log Replay (historical re-parsing)
Customer instance ID: <YOUR_INSTANCE_ID>
Google Cloud project ID: <YOUR_PROJECT_ID>
Target log_type: <LOG_TYPE_LABEL>
Start timestamp (RFC 3339 UTC): 2026-06-01T00:00:00Z
End timestamp (RFC 3339 UTC): 2026-08-31T23:59:59Z
Active parser or extension ID: <ACTIVE_PARSER_NAME_OR_EXTENSION_ID>
Business justification: Retroactive UDM field normalization for active parser update

```
## Troubleshooting
This section outlines performance expectations and provides self-service fixes for common Log Replay issues.
### Latency and limits
After Google Cloud Support initiates the Log Replay task, the process runs asynchronously in the backend. Processing time depends on the overall volume of logs within the specified time window. As the task processes historical raw logs, newly generated UDM records incrementally replace earlier UDM records for that time range. Don't submit duplicate support requests for the same log type and time window while a replay task is running.
### Error remediation
Use this table to resolve common issues when requesting or validating a Log Replay task.    Issue Description Fix     Request rejected due to inactive parser The requested custom parser or parser extension is in Draft or Pending status. In SIEM Settings > Parsers, activate the parser configuration, verify that live logs parse as expected, and resubmit the support case.   Request rejected due to time window limit The requested start timestamp is more than 180 days in the past. Adjust the start and end timestamps in your support case description to fall within the supported 180-day retention window.   Updated UDM fields missing in search UDM search results for the target time window don't show the new field mappings yet. Wait for the asynchronous backend replay task to finish processing the full time range, and verify your query syntax in SIEM Search.
### Validation and testing
After Google Cloud Support confirms that the Log Replay task is complete, verify the updated UDM records in your environment:  In the Google SecOps console, go to Investigation > SIEM Search. Set the time range picker to match the historical start and end timestamps from your replay request. Run a UDM search query targeting the newly mapped UDM fields for your `log_type` to confirm that historical events display the normalized attributes.