# Source: https://docs.cloud.google.com/chronicle/docs/investigation/Investigate-alert-entity-context

# Investigate alerts and entity context
Supported in:    Google secops   SIEM
This guide is for investigators who want to identify correlated activities and evaluate risk profiles from alerts. You can use this guide to understand how to pivot from an alert to an entity's timeline. Successful investigation can reduce the time-to-triage for complex incidents and help you focus on high-impact threats first.
## Common use cases
This section lists some common use cases.
### Triage and case prioritization
Objective: Determine which alerts require immediate escalation by evaluating the risk profile of the involved entities. This approach moves beyond chronological processing by identifying alerts that pose the greatest organizational threat.
Workflow:
Open the Alerts dashboard and view an alert.
Copy the asset ID or username and pivot to Risk Analytics.
If the entity already has a high entity risk score, prioritize this case over alerts involving low risk entities.
Outcome: Limited SOC resources can focus on high impact threats first.
### Analyse scope of impact of an alert
Objective: Understand the full scope of an incident by tracking the alert's correlated activity. By tracking the correlated activity across the environment, you can map out the relationship between compromised systems and accounts to visualize how a threat has migrated.
Workflow:
Open the Alerts dashboard and view a high risk alert.
Go the graph tab to view entity context graph (ECG) relationships.
For each related entity, pivot to the Detections timeline in Risk Analytics.
Look for overlapping detection patterns to map how the threat may have spread.
Outcome: A comprehensive map of the incident that identifies affected systems and accounts.
### Lateral movement investigation
Objective: Proactively identify malicious behavior by comparing UDM events against a baseline of normal behavioral history. You can identify subtle anomalies in internal communications and access patterns that suggest an attacker is moving through the network.
Workflow:
Select an entity and review its behavioral history (usual login times or file access).
Search UDM events for deviations, such as an asset suddenly communicating with a new internal IP address or a user accessing a sensitive application for the first time.
Evaluate if these anomalies have caused a recent spike in the entity risk score, even if a formal alert has not yet been triggered.
By linking the UDM events to the entity's history, you can distinguish between a legitimate business change and potential lateral movement.
Outcome: Early detection of threats that bypass signature-based alerting.
## Before you begin
Make sure you have the following in place:
Permissions: You must have access to the Alerts dashboard, Risk Analytics dashboard, and UDM Search capabilities.
Environment check: Enable ECG and Risk Analytics to ensure that they are ingesting data to populate timelines.
## Investigate detections and entity context
Complete the following steps to manually link an alert to a risk profile and analyze the historical activity of the involved assets.
### Identify the entity from an alert
Identify the specific asset or user involved in the alert to establish a starting point for your investigation.
Go to the Alerts page.
In the Detections table, click the alert name to open the alert page. Note: If the Inputs table only displays a file hash, you won't see a direct asset ID. You must run a UDM search using that hash to identify the specific asset associated with it.
Locate the Inputs table.
If the table contains Entities, do the following:
Click the entity name to open the Entity context tab.
Identify the related entities (for example, a specific hash, IP address, or asset name).
Copy the Asset ID or Username.
If the table contains Detections or Events, do the following:
For detections, click the Detection row to view the underlying events.
Click the event row to open the Event viewer tab.
In the Entities tab, identify the related entities (for example, a specific hash, IP address, or asset name).  Note: If only a hash is visible, run a UDM search to identify the specific asset associated with that hash.  Copy the Asset ID or Username identified in the alert.
### Pivot to risk analytics
Use the identifier found in the alert to access the entity's broader risk profile within the analytics dashboard.
Go to the Risk Analytics dashboard.
Go to the Entities tab and paste the copied identifier into the search bar.
From the results, click the entity name to view the Detections Timeline of the asset. The Detections Timeline gives the historical context of the asset or user.
### Analyze detections timeline
Examine the list of detections (for example, `19 detections`) that contributed to the current risk score.
Review the timeline to see how UDM events and ECG relationships have evolved over time to determine the severity of the incident.
Note: If you ignore the timeline and only look at the single alert, you might miss overlapping detection patterns that indicate a larger, coordinated threat.
## Troubleshooting
This section outlines performance expectations and provides self-service fixes for common investigation issues.
### Latency and limits
Be aware that the correlation of new events into your timeline takes approximately 10–15 minutes due to sync latency. Avoid re-running searches or filing a support ticket during this window.
### Common investigation issues
Use the following table to solve common investigation gaps.   Issue  Description  Fix    Missing asset ID  Your alert only shows a file hash or IP address without a linked asset.  Run a UDM search for that hash or IP to identify the associated `principal.asset_id`.    Empty timeline  The entity exists in Risk Analytics but no detections are listed.  Ensure that the entity has triggered detections. If it has, verify whether your ECG ingestion pipeline is active.
### Validation and testing
After your investigation, you can optionally use the UDM Search to verify that specific events found in the timeline exist as raw logs, which confirms the accuracy of the correlation.