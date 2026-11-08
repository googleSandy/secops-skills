# Source: https://docs.cloud.google.com/chronicle/docs/investigation/rule-exclusion-api

# Manage rule exclusions
Supported in:    Google SecOps   SIEM
This document explains how to programmatically manage rule exclusions in Google Security Operations using the API. Exclusions serve as filters that you define based on Unified Data Model (UDM) fields to prevent specific detections from generating alerts. By identifying known or safe activities, these filters stop unnecessary noise in your dashboard. Note: Rule exclusions apply only to curated rules and curated rule sets. Custom rules aren't supported. To suppress alerts from custom rules, add exclusion logic to the YARA-L rule definition, or use data tables to maintain exclusion lists across multiple rules. For more information, see Configure alert suppression.  Caution: Don't apply a rule exclusion directly to a composite rule. You must apply the exclusion to the foundational underlying rules that feed into the composite rule. This is because rule exclusions are evaluated against UDM fields (like `principal.user.userid`), but composite rules trigger based on other detections rather than UDM fields. If you apply a rule exclusion directly to a composite rule, the exclusion will fail to match, and the event won't get excluded.
To find the foundational rule, you can inspect the composite rule definition in the Google SecOps console (under Content Hub > Curated Detections) and review the `events:` section of the YARA-L logic to identify the foundational rule names.
## Create an exclusion with outcome filters
You can create a new exclusion rule programmatically to suppress specific detection findings that match your defined criteria, thereby reducing noise and prioritizing high-fidelity alerts.
Use the `POST` endpoint to define the suppression logic. All filters with the `outcomeFilters` array are linked by an implicit `AND` clause.
Method: `POST`
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
      "outcome_value": "127.0.0.1",
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
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID/findingsRefinements/REFINEMENT_ID
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
REFINEMENT_ID: The unique ID of the `FindingsRefinement` resource.
Example:
```
GET https://us-chronicle.googleapis.com/v1/projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/findingsRefinements/fr_00001111-2222-3333-4444-555566667777

```
## Apply an exclusion to a curated rule or rule set
To activate an exclusion, apply it to specific curated rules or curated rule sets by updating its `FindingsRefinementDeployment` resource. Use the `update_mask` query parameter to specify which fields to update in the deployment. Note: The `rules` field in `detectionExclusionApplication` isn't supported for custom rules. If you include custom rule resource names in `rules`, the API returns `200 OK` without attaching the exclusion to those rules.
Method: `PATCH`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID/findingsRefinements/REFINEMENT_ID/deployment
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
REFINEMENT_ID: The unique ID of the `FindingsRefinement` resource.
Example:
```
PATCH https://us-chronicle.googleapis.com/v1/projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/findingsRefinements/fr_00001111-2222-3333-4444-555566667777/deployment?update_mask=enabled,detectionExclusionApplication

```
Request body:
```
{
  "name": "projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/findingsRefinements/fr_00001111-2222-3333-4444-555566667777/deployment",
  "enabled": true,
  "detectionExclusionApplication": {
    "curatedRuleSets": [
      "projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/curatedRuleSetCategories/CATEGORY_ID/curatedRuleSets/RULE_SET_ID"
    ],
    "curatedRules": [
      "projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/curatedRules/RULE_ID"
    ]
  }
}

```
In the request body, specify the lists of curated rule set resource names and curated rule resource names in the `curatedRuleSets` and `curatedRules` arrays. Replace CATEGORY_ID, RULE_SET_ID, and RULE_ID with your curated rule set category ID, curated rule set ID, and curated rule ID.
## Access the deployment for the exclusion
After you create or update an exclusion, use this endpoint to verify which curated rules or curated rule sets the exclusion is deployed to.
Method: `GET`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID/findingsRefinements/REFINEMENT_ID/deployment
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
Use the following endpoint to get the list of `FindingsRefinementDeployment` resources created within your instance.
Method: `GET`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID:listAllFindingsRefinementDeployments
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
Use the `filter` parameter to filter on `detection_exclusion_application.curated_rules` or `detection_exclusion_application.curated_rule_sets`.
## Test an exclusion using the API
The following endpoint tests an exclusion against detections from specified curated rules and curated rule sets to validate how effectively it suppresses unwanted detections. The console uses the last 30 days of detections for testing.
Method: `POST`
Endpoint:
```
https://REGION-chronicle.googleapis.com/v1alpha/projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID:testFindingsRefinement
```
Replace the following:
REGION: The Google Cloud region for the Google SecOps instance.
PROJECT_ID: Your Google Cloud project ID.
LOCATION: The location of the Google SecOps instance (often the same as the region).
INSTANCE_ID: The ID of the Google SecOps instance.
Example:
```
POST https://us-chronicle.googleapis.com/v1alpha/projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210:testFindingsRefinement

```
Request body:
```
{
  "type": "DETECTION_EXCLUSION",
  "query": "principal.hostname = \"altostrat.com\"",
  "outcomeFilters": [
    {
      "outcome_variable": "ip",
      "outcome_value": "127.0.0.1",
      "outcome_filter_operator": "EQUAL"
    },
    {
      "outcome_variable": "hostnames",
      "outcome_value": "altostrat.com",
      "outcome_filter_operator": "CONTAINS"
    }
  ],
  "interval": {
    "start_time": {
      "seconds": 1756684800
    },
    "end_time": {
      "seconds": 1759276800
    }
  },
  "detectionExclusionApplication": {
    "curatedRuleSets": [
      "projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/curatedRuleSetCategories/CATEGORY_ID/curatedRuleSets/RULE_SET_ID"
    ],
    "curatedRules": [
      "projects/0123456789/locations/us/instances/01234567-89ab-cdef-fedc-ba9876543210/curatedRules/RULE_ID"
    ]
  }
}

```
In the previous example, the `interval` field tests detections from September 1, 2025, at 00:00 UTC (`1756684800`) to October 1, 2025, at 00:00 UTC (`1759276800`). In `detectionExclusionApplication`, specify the curated rule set and curated rule resource names to test against by replacing CATEGORY_ID, RULE_SET_ID, and RULE_ID.
## Query syntax and field rules
The `findingsRefinements.query` field supports a restricted subset of YARA-L 2.0 syntax rather than full UDM search (`udmSearch`) syntax. Because these two query syntaxes differ, a query that succeeds in `udmSearch` can fail with a `400 INVALID_ARGUMENT` error in an exclusion.
The following sections describe the syntax rules for the `findingsRefinements.query` field:  Boolean grammar Supported operators and literals Supported UDM fields and path depth limits
To validate an exclusion query before deployment, call the `testFindingsRefinement` endpoint instead of `udmSearch`.
### Boolean grammar
The `findingsRefinements.query` field requires flat Conjunctive Normal Form (CNF) boolean syntax. In flat CNF, you join one or more clauses with `AND`, and each parenthesized clause contains only flat `OR` comparisons without nested parentheses.
The `findingsRefinements.query` field supports the following boolean structures:  A single comparison or a flat sequence of `OR` comparisons, such as `field_a = "val_1" OR field_b = "val_2"`. Multiple clauses joined by `AND` (or implicit whitespace `AND`), where each parenthesized clause contains only flat `OR` comparisons. For example, `field_a = "val_1" AND (field_b = "val_2" OR field_c = "val_3")`. Prefix `NOT` before a single comparison, such as `NOT principal.hostname = "scanner.example.com"`.
The `findingsRefinements.query` field rejects the following boolean structures with a `400 INVALID_ARGUMENT` error:  Nested parentheses, such as `A AND (B OR (C AND D))`. Logical `OR` operators between parenthesized clauses, such as `(A AND B) OR (C AND D)`.
You can rewrite nested logic such as `A OR (B AND C)` in flat CNF as `(A OR B) AND (A OR C)`. For complex `OR`-of-`AND` conditions where CNF expansion grows too large, create separate `FindingsRefinement` resources for each `AND` branch.
### Supported operators and literals
The following table lists each query feature, its support in `findingsRefinements.query`, and a valid example or alternative:    Feature Support in `findingsRefinements.query` Example or alternative     Comparison operators Supports `=`, `!=`, `<`, `<=`, `>`, and `>=`. String, regular expression, and map comparisons support `=` and `!=`. `metadata.log_type = "WINDOWS_SYSMON"`   Regular expressions Supports slash-delimited regular expressions (`/.../`) on string and map fields. `principal.hostname = /^scanner-[0-9]+\.example\.com$/`   Case-insensitive modifier Supports `nocase` on string and regular expression comparisons. Enum fields don't support `nocase`. `principal.user.userid = "admin" nocase`   Literals Supports double-quoted strings, integers, floats, booleans (`true` or `false`), and base64 byte literals (`b"..."`). `security_result.about.file.sha256 = "e3b0c4..."`   CIDR range matching Supports the `CIDR_RANGE` keyword on IP address fields. `principal.ip = CIDR_RANGE "192.0.2.0/24"`   YARA-L functions Doesn't support YARA-L functions, such as `net.ip_in_range_cidr` or `re.regex`. Use `CIDR_RANGE` for IP subnets or `/.../` for regular expressions.   Reference lists and data tables Doesn't support reference list (`%list_name`) or data table lookups in exclusion queries. Enumerate values with flat `OR` comparisons or `outcomeFilters`.
### Supported UDM fields and path depth limits
The `findingsRefinements.query` field enforces the following UDM field rules:  Field paths support a maximum of 6 dot-separated segments, such as `target.process.file.sha256` (4 segments) or `target.resource.attribute.labels["env"]` (4 segments). Field paths with 7 or more dot-separated segments fail validation with a `400 INVALID_ARGUMENT` (`Not a valid field path`) error. For example, `target.process.file.signature_info.sigcheck.signers.name` has 7 segments and is rejected. Leaf fields support scalar (`string`, integer, float, and `bool`), `enum`, and `bytes` data types. Map and `Label` fields support bracket-keyed lookups, such as `additional.fields["key"] = "value"` and `target.resource.attribute.labels["project"] = "prod"`. Grouped UDM search aliases, such as `ip`, `hostname`, `user`, and `hash`, are supported alongside full UDM event field paths. Entity graph paths (`graph.*`) and unkeyed `message` fields aren't supported in exclusion queries.
## Limitations
All exclusions (with or without outcome filters) must specify a `query` field. To create an exclusion using only the `outcomeFilters` field, include the required `FindingsRefinement` fields and set the `query` field to a `match-all` regular expression:
```
{
  "displayName": "Exclusion with only outcome filters",
  "type": "DETECTION_EXCLUSION",
  "query": "principal.hostname = /.*/",
  "outcomeFilters": [
    {
      "outcome_variable": "ip",
      "outcome_value": "127.0.0.1",
      "outcome_filter_operator": "EQUAL"
    }
  ]
}

```
The regular expression matches any hostname. Therefore, this query matches all detections. Consequently, the effective filtering is determined solely by the outcome filters.
Exclusions don't support a time to live (TTL) configuration. However, you can create a one-time TTL by calculating the specific expiration time and adding a timestamp condition in the exclusion definition. For example, to set an exclusion to expire on January 1, 2026, at 00:00 UTC (`1767225600`), specify the query as follows:
```
{
  "displayName": "Exclusion with expiration timestamp",
  "type": "DETECTION_EXCLUSION",
  "query": "metadata.event_timestamp.seconds < 1767225600",
  "outcomeFilters": [
    {
      "outcome_variable": "ip",
      "outcome_value": "127.0.0.1",
      "outcome_filter_operator": "EQUAL"
    }
  ]
}

```
Include the other required `FindingsRefinement` fields and your outcome filters as needed. The previous example confirms that only detections created by events with a timestamp before January 1, 2026, at 00:00 UTC (`1767225600`) are suppressed.
Note: This might not display properly in the Edit Exclusions window of the user interface because it only supports `string` fields.
Composite rules: Don't apply a rule exclusion directly to a composite rule. You must apply the exclusion to the foundational underlying rules that feed into the composite rule. This is because rule exclusions are evaluated against UDM fields (like `principal.user.userid`), but composite rules trigger based on other detections rather than UDM fields. If you apply a rule exclusion directly to a composite rule, the exclusion will fail to match, and the event won't get excluded.
To find the foundational rule, you can inspect the composite rule definition in the Google SecOps console (under Content Hub > Curated Detections) and review the `events:` section of the YARA-L logic to identify the foundational rule names.
Query syntax and field depth: Exclusion queries must use flat Conjunctive Normal Form (CNF) boolean syntax and UDM field paths with a maximum of 6 dot-separated segments. For more information, see Query syntax and field rules.
Custom rules: Don't apply a rule exclusion to a custom rule. Rule exclusions apply only to curated rules and curated rule sets using the `curatedRules` and `curatedRuleSets` fields. If you include `rules` in `detectionExclusionApplication`, the API ignores the field without applying the exclusion. To suppress alerts from custom rules, add exclusion logic to the YARA-L rule definition, or use data tables to maintain exclusion lists across multiple rules. For more information, see Filter UDM event and entity data using a data table and Left anti-join examples in rules.