# Source: https://docs.cloud.google.com/chronicle/docs/investigation/rule-exclusion-api

# Manage rule exclusion using the API
Supported in:    Google secops   SIEM
This document explains how to programmatically manage rule exclusions in Google Security Operations using the API. Exclusions serve as filters that you define based on Unified Data Model (UDM) fields to prevent specific detections from generating alerts. By identifying known or safe activities, these filters stop unnecessary noise in your dashboard.
## Create an exclusion with outcome filters
You can create a new exclusion rule programmatically to suppress specific detection findings that match your defined criteria, thereby reducing noise and prioritizing high-fidelity alerts.
Use the `POST` endpoint to define the suppression logic. All filters with the `outcomeFilters` array are linked by an implicit `AND` clause.
Method: `POST`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
Example:
```
POST https://us-chronicle.googleapis.com/v1/projects/my-project/locations/us/instances/my-instance/findingsRefinements

```
Request body:
```
  {
  "displayName": "Exclusion with outcome filters",
  "type": "DETECTION_EXCLUSION",
  "query": "principal.hostname = \"altostrat.com\"",
  "outcomeFilters": [
    {
      "outcome_variable": "ip",
      "outcome_value": "127.0.01",
      "outcome_filter_operator": "EQUAL"
    },
    {
      "outcome_variable": "hostnames",
      "outcome_value": "altostrat.com",
      "outcome_filter_operator": "CONTAINS"
    }
  ]
}

```
The example demonstrates how to define suppression logic where multiple filters in the `outcomeFilters` array are linked by an implicit `AND` clause.
Required fields: `displayName`, `type`, `query`
System-generated fields: Don't specify `name`, `createTime`, or `updateTime`. These are managed by the system and are ignored or cause errors if included in the request.
The suppression logic follows an `AND` relationship. The request creates an exclusion that suppresses any detections that have an event with the following:
"altostrat.com" as the principal hostname
An outcome variable `ip` with a value of `127.0.0.1`
An outcome variable `hostnames` with at least one of its aggregated values being `altostrat.com`.
All filters specified within the exclusion are implicitly linked by an `AND` clause.
API response: The API returns the `FindingsRefinement` resource name.
The `FindingsRefinement` resource contains the core suppression logic (the query and outcome filters). The resource name (ID) is used for subsequent operations on the exclusion
## Access an exclusion
Use the `GET` endpoint to do the following:
Get the details of a single exclusion definition by its unique ID.
When you have a specific `refinement-id` and need to verify the exact query or outcome filters it contains.
Method: `GET`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID/findingsRefinements
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
Example:
```
GET https://us-chronicle.googleapis.com/v1/projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/findingsRefinements/fr_00001111-2222-3333-4444-555566667777

```
## Apply an exclusion to a rule or rule set
You must apply the exclusion to specific rules or curated rule sets. When you apply the exclusion to a rule or rule set, it creates a `FindingsRefinementDeployment` resource. You can use this resource to determine the custom rules, curated rules, or curated rule sets that apply to the `FindingsRefinement` resource. You can then specify the update_mask parameter in the API request to indicate which fields in the `FindingsRefinementDeployment` to update.
Method: `PATCH`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID/findingsRefinements/REFINEMENT_ID
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
REFINEMENT_ID: The unique ID of the Findings Refinement.
Example:
```
 PATCH https://us-chronicle.googleapis.com/v1/projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/findingsRefinements/fr_00001111-2222-3333-4444-555566667777?update_mask=enabled,detectionExclusionApplication

```
Request body:
```

  {
  "name": "projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/findingsRefinements/fr_00001111-2222-3333-4444-555566667777"
  "enabled": true,
  "detectionExclusionApplication": {
    "curatedRuleSets": [
      ...list curated rule set resource names
    ],
    "curatedRules": [
      ...list curated rule resource names
    ],
    "rules": [
      ...list rule resource names
    ],
  }
}

```
When you apply the exclusion to a rule or rule set, the system creates a `FindingsRefinementDeployment` resource. This resource determines which custom rules, curated rules, and curated rule sets apply to the `FindingsRefinement` resource. You can also include the `update_mask` parameter in the API request to specify which fields in the `FindingsRefinementDeployment` to update.
## Access the deployment for the exclusion
After you create or update an exclusion, use this endpoint to verify which rules or rule sets that specific exclusion is deployed to.
Method: `GET`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID/findingsRefinements/REFINEMENT_ID
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
REFINEMENT_ID: The unique ID of the Findings Refinement.
Example:
```
   GET https://us-chronicle.googleapis.com/v1/projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/findingsRefinements/fr_00001111-2222-3333-4444-555566667777/deployment

```
## List all exclusions
Use this endpoint to retrieve the list of `findingsRefinements` resources.
Method: `GET`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID/findingsRefinements
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
Example:
```
GET https://us-chronicle.googleapis.com/v1/projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/findingsRefinements

```
Optional query parameters: `pageSize`, `pageToken`
You can use the optional parameters to list more results similar to other list endpoints within the API.
## List all exclusion deployments
Use this endpoint to get the list of `FindingsRefinement` resources created within your instance.
Method: `GET`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID/findingsRefinements
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
Example:
```
  GET https://us-chronicle.googleapis.com/v1/projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210:listAllFindingsRefinementDeployments

```
Optional query parameters:
Use the `pageSize` and `pageToken` parameters to list more results similar to other list endpoints within the API.
Use the `filter` parameter to filter on the rules or rule sets that have exclusions applied on them.
## Test an exclusion using the API
This endpoint tests the exclusion against detections from the specified rules and rule sets, and then validates the effectiveness of the exclusion in suppressing unwanted detections. The UI uses the last 30 days of detections for testing.
Method: `POST`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID:testFindingsRefinement
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
Example:
```
POST https://us-chronicle.googleapis.com/v1/projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210:testFindingsRefinement

```
Request body:
```
 {
  "type": "DETECTION_EXCLUSION",
  "query": "principal.hostname = \"altostrat.com\"",
  "outcomeFilters": [
    {
      "outcome_variable": "ip",
      "outcome_value": "127.0.01",
      "outcome_filter_operator": "EQUAL",
    },
    {
      "outcome_variable": "hostnames",
      "outcome_value": "altostrat.com",
      "outcome_filter_operator": "CONTAINS",
    },
  ]
  "interval": {
    "start_time": {
      "seconds": 1756684800, // Sep. 1 2025 00:00 UTC
    },
    "end_time": {
      "seconds": 1759276800, // Oct. 1 2025 00:00 UTC
    },
  },
  "detectionExclusionApplication": {
    "curatedRuleSets": [
      ...curated rule set resource names
    ],
    "curatedRules": [
      ...curated rule resource names
    ],
    "rules": [
      ...rule resource names
    ],
  }
}

```
This endpoint tests the exclusion over detections that have been generated in the rules and rule sets specified in the request. It helps determine how effective the exclusion is in suppressing detections that shouldn't be generated. The system uses the last 30 days of detections as the time range to test the exclusions over.
## Limitations
All exclusions (with or without outcome filters) must specify a `query` field. To create an exclusion with only `outcomeFilters`, specify a `match-all` regular expression.
```

  ...other fields in FindingsRefinement

  query: "principal.hostname = /.*/"

  outcomeFilters: [ your outcome filters ]

```
The regular expression matches any hostname. Therefore, this query matches all detections. Consequently, the effective filtering is determined solely by the outcome filters.
Exclusions don't support a time to live (TTL) configuration. However, you can create a one-time TTL by calculating the specific expiration time and adding a timestamp condition in the exclusion definition. For example, to set an exclusion to expire at the end of the year, specify the query as follows:
```

  ...other fields in FindingsRefinement

  query: "metadata.event_timestamp.seconds < 1767225600" // Jan 1 2026 00:00 UTC

  outcomeFilters: [your outcome filters]

```
This example confirms that only detections created by events with a timestamp before the end of the year are suppressed.
Note: This might not display properly in the Edit Exclusions window of the user interface because it only supports `string` fields.