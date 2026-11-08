# Source: https://docs.cloud.google.com/chronicle/docs/investigation/search-lro-api

# Asynchronous Search APIs
Supported in:    Google SecOps   SIEM
The Search platform in Google Security Operations lets you use asynchronous APIs for long-running queries that return large result sets of up to 1 million results. These APIs let you initiate searches across data sources, including Unified Data Model (UDM) events, detections, data tables, and Entity Context Graph (ECG), without blocking your application. When you run a search query using a long-running operation (LRO) API, you receive an operation ID. You can use this ID to monitor the operation status and get the results page by page.
## Prerequisites
To use long-running operation APIs, the calling principal requires specific Identity and Access Management (IAM) permissions.
To perform the following actions, you must have the corresponding IAM permissions:  Initiate a search: `chronicle.searchSessions.search` List results: `chronicle.searchedResults.list` on the `SearchSession` resource.
Make sure that the calling principal has a role that grants these permissions, for example, the Chronicle API Viewer, Chronicle API Editor, or Chronicle API Admin role.
## Run a search using LRO APIs
Follow these steps to run a search using the LRO APIs:  Initiate the search. Monitor the operation. Fetch the results.
### Initiate the search
Send a `POST` request to the `search` custom method on the Google SecOps instance.  Endpoint: `POST /{$api_version}/projects/{project}/locations/{location}/instances/{instance}:search` Method: `Search` Request body: `SearchRequest`
The following example shows a `SearchRequest` object:
```
{
  "parent": "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID",
  "query": "metadata.event_type = \"USER_LOGIN\"",
  "time_range": {},
  "start_time": "2026-03-16T14:40:13Z",
  "endTime": "2026-03-16T15:40:13Z",
  "dialect": "YL2"
}

```
The request requires the following key parameters:  `query`: The search query string. `time_range`: The time interval for the search. `dialect`: Specifies the language dialect as `YL2`.  The `SQL` dialect isn't supported for asynchronous LRO result retrieval using `ListSearchedResults` (`searchedResults.list`). The `RAW_LOG` dialect is in Preview and might return a `501 UNIMPLEMENTED` error if it isn't enabled for your instance.  `result_limit`: Optional. The maximum number of rows to materialize. The default value is `10000`, and the maximum value is `1000000`. `simulated_data_visibility` (or `simulatedDataVisibility` in JSON): Optional. Controls whether search results include simulated events. Set to `SIMULATED_DATA_INCLUDED` to include simulated events in search results. If unspecified, this parameter defaults to `SIMULATED_DATA_EXCLUDED`, which excludes simulated events.
This call returns a `google.longrunning.Operation` object.
The following example shows a successful operation response:
```
{
  "name": "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/operations/OPERATION_ID",
  "metadata": {
    "@type": "[type.googleapis.com/google.cloud.chronicle.v1main.SearchOperationMetadata](https://type.googleapis.com/google.cloud.chronicle.v1main.SearchOperationMetadata)",
    "state": "RUNNING",
    "start_time": "2026-03-13T10:00:00Z"
  }
}

```
The `state: RUNNING` field indicates that the search is in progress.
### Monitor the operation
Poll the status of the LRO by using the standard `GetOperation` method from the `google.longrunning.Operations` service. Use the `name` value from the previous response.  Endpoint: `GET /{$api_version}/projects/{project}/locations/{location}/instances/{instance}/operations/{operationID}`
Continue polling until the `done` field in the `GetOperation` response returns `true`.  If the operation is successful, the `metadata.state` field returns `SUCCEEDED`, and the response field contains the created `SearchSession` resource. If the operation fails, the `done` field returns `true`, and the error field contains the related failure details.
The following example shows a successful `GetOperation` response:
```
{
  "name": "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/operations/OPERATION_ID",
  "metadata": {
    "@type": "[type.googleapis.com/google.cloud.chronicle.v1main.SearchOperation](https://type.googleapis.com/google.cloud.chronicle.v1main.SearchOperation) Metadata",
    "state": "SUCCEEDED",
    "startTime": "2026-03-16T15:42:11.037506921Z"
  },
  "endTime": "2026-03-16T15:42:17.504730842Z",
  "expireTime": "2026-03-17T15:42:17.504731874Z",
  "progress": 100,
  "done": true,
  "response": {
    "@type": "[type.googleapis.com/google.cloud.chronicle.v1main.SearchSession](https://type.googleapis.com/google.cloud.chronicle.v1main.SearchSession)",
    "name": "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/searchSessions/SEARCH_SESSION_ID",
    "query": "metadata.event_type = \"USER_LOGIN\"",
    "timeRange": {},
    "startTime": "2026-03-16T14:40:13Z",
    "endTime": "2026-03-16T15:40:13Z",
    "dialect": "YL2",
    "metadata": {
      "operationId": "OPERATION_ID",
      "startTime": "2026-03-16T15:42:11.037506921Z",
      "endTime": "2026-03-16T15:42:17.504730842Z",
      "expireTime": "2026-03-17T15:42:17.504731874Z",
      "resultRowCount": 10000,
      "moreDataAvailable": true
    }
  }
}

```
The `SearchSession` resource name format is `projects/{project}/locations/{location}/instances/{instance}/searchSessions/{search_session}`.
The successful response contains the following key fields:  `done`: When set to `true`, the operation is complete. `state`: When set to `SUCCEEDED`, the search finished successfully. `response.name`: The resource name of the `SearchSession`. Use this value as the parent property in the next step. `response.metadata.resultRowCount`: Indicates the total number of rows found. `response.metadata.moreDataAvailable`: Indicates that the number of available results exceeds the defined return limit.
#### List LRO operations
To list LRO operations, use the `ListOperations` method from the `google.longrunning.Operations` service. Use the `name` value from the previous response.  Endpoint: `GET /{$api_version}/projects/{project}/locations/{location}/instances/{instance}`
To list search LRO operations from the past 24 hours, specify the `name:"operations/s-lro-"` filter, including the trailing hyphen. Note: This filter is required when you call `ListOperations` (`operations.list`) to retrieve search operations. If you call `ListOperations` without this filter, the response returns only retrohunt operations and omits search operations. In addition, the `CancelOperation` (`operations.cancel`) and `DeleteOperation` (`operations.delete`) methods aren't supported for `s-lro-` search operations.
The following example shows a successful `ListOperations` request:
```
google.longrunning.ListOperationsRequest {
  name: "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID"
  filter: "name:\"operations/s-lro-\""
  page_size: 100
}

```
The following example shows a successful `ListOperations` response:
```
{
  operations {
    name: "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/operations/OPERATION_ID_1"
    metadata {
      type_url: "[type.googleapis.com/google.cloud.chronicle.v1main.SearchOperation](https://type.googleapis.com/google.cloud.chronicle.v1main.SearchOperation) Metadata"
      value: "\b\002\022\f\b\367\304\363\316\006\020\317\352\232\240\003\032\f\b\237\307\363\316\006\020\326\334\351\311\001\"\f\b\237\352\370\316\006\020\352\342\351\311\001(d"
    }
    done: true
    response {
      type_url: "[type.googleapis.com/google.cloud.chronicle.v1main.SearchSession](https://type.googleapis.com/google.cloud.chronicle.v1main.SearchSession)"
      value: "\n\213\001projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/searchSessions/OPERATION_ID_11022\bip != \"\"\032\020\n\006\b\251\255\334\316\006\022\006\b\351\345\336\316\006\0012\\\n*OPERATION_ID_1\022\f\b\367\304\363\316\006\020\317\352\232\240\003\032\f\b\237\307\363\316\006\020\326\334\351\311\001\"\f\b\237\352\370\316\006\020\352\342\351\311\001(\300\204=0\001"
    }
  }
  operations {
    name: "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/operations/OPERATION_ID_2"
    metadata {
      type_url: "[type.googleapis.com/google.cloud.chronicle.v1main.SearchOperationMetadata](https://type.googleapis.com/google.cloud.chronicle.v1main.SearchOperationMetadata)"
      value: "\b\002\022\f\b\200\305\363\316\006\020\324\262\367\225\001\032\v\b\241\307\363\316\006\020\321\261\333?\"\v\b\241\352\370\316\006\020\317\264\333?(d"
    }
    done: true
    response {
      type_url: "[type.googleapis.com/google.cloud.chronicle.v1main.SearchSession](https://type.googleapis.com/google.cloud.chronicle.v1main.SearchSession)"
      value: "\n\213\001projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/searchSessions/OPERATION_ID_2\022\bip != \"\"\0321020\n\006\b\251\255\334\316\006\022\006\b\351\345\336\316\006\0012Z\n*OPERATION_ID_2\022\f\b\200\305\363\316\006\0201324\262\367\225\001\032\v\b\241\307\363\316\006\020\321\261\333?\"\v\b\241\352\370\316\006\020\317\264\333?(\300\204=0\001"
    }
  }
}

```
### Fetch the results
After the operation state returns `SUCCEEDED`, use the `ListSearchedResults()` method to retrieve the search results.  Endpoint: `GET /{$api_version}/{parent=projects/*/locations/*/instances/*/searchSessions/*}/searchedResults` Method: `ListSearchedResults` Request parameters: `ListSearchedResultsRequest`
The following example shows a `ListSearchedResultsRequest` that retrieves three results and skips the first five:
```
// GET
/v1alpha/projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/searchSessions/SEARCH_SESSION_ID/searchedResults?page_size=3&skip=5

```
The request supports the following query parameters:  `page_size`: The maximum number of results to return per page. The default value is 100, and the maximum value is 10000. `page_token`: The token from a previous `ListSearchedResultsResponse` used to retrieve the next page.
`order_by` (or `orderBy` in JSON): Optional. The field used to sort the results. When you omit `order_by`, UDM event results are sorted by `udm.metadata.event_timestamp` in descending order by default, returning the most recent events first. When you specify a field path in `order_by` without a direction suffix, such as `udm.principal.hostname`, results are sorted in ascending order by default. Don't append `asc`, because the `asc` suffix isn't supported and returns a `400 INVALID_ARGUMENT` error. To sort results in descending order, append the `desc` suffix to the field path, such as `udm.metadata.event_timestamp desc`. Multi-column sorting isn't supported.
`UDM events (eventRecord)`: Use fully qualified paths within the `udm` field, such as `udm.metadata.event_timestamp desc` or `udm.principal.hostname`. Column names such as `hostname`, `user`, `process name`, and `event type` are also supported.
The default sort order is `udm.metadata.event_timestamp` in descending order, which returns the most recent events first.
`Entities / ECG (entityContextRecord)`: Use paths within the `entity` field, such as `graph.entity.ip` or `graph.entity.ip desc`.
`data tables (dataTableRecord)`: Use the `%<table_alias>.<column_name>` format. For example, `%dt.user desc`.
The default value is the first data table column.
`Detections (DetectionRecord)`: Use the keyword `detection` followed by the path, for example, `detection.id`.
Joins: For events and entities, use the placeholder variable that defines them. For all other sources, the format remains the same.
For example:  ECG (UDM-ECG join): Entity: `$e1.graph.entity.hostname` UDM (All joins with UDM): `$e1.principal.ip` Data table (UDM-Data table join): `%<table_alias>.<column_name>`
Predefined aliases such as `hostname`, `user`, `process name`, and `event type` are also supported. For these, use the format `$e1.hostname.at`.
`skip`: Optional. The number of results to skip. Don't use this parameter with `page_token`.  Default sorting (`udm.metadata.event_timestamp`) isn't unique across events that share the same timestamp. In addition, the sort order for the search results is set on the first `ListSearchedResults` (`searchedResults.list`) call. When you paginate with `skip`, especially across parallel requests, specify a unique sort field such as `udm.metadata.id` in the `order_by` parameter. Alternatively, fetch the first page before sending parallel `skip` requests so that the sort order is already set.
The following example shows a successful `ListSearchedResultsResponse` response (with additional UDM fields and repeated event structures omitted for brevity):
```
{
  "searchedResults": [
    {
      "name": "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/searchSessions/SEARCH_SESSION_ID/searchedResults/RESULT_ID",
      "resultRow": {
        "eventRecord": {
          "event": {
            "name": "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/events/EVENT_ID",
            "udm": {
              "metadata": {
                "eventTimestamp": "2026-03-16T14:45:18Z",
                "eventType": "USER_LOGIN",
                "vendorName": "Microsoft",
                "productName": "Azure AD"
              }
            }
          },
          "eventLogToken": "EVENT_LOG_TOKEN"
        }
      }
    },
    {
      "name": "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/searchSessions/SEARCH_SESSION_ID/searchedResults/RESULT_ID",
      "resultRow": {
        "eventRecord": {}
      }
    },
    {
      "name": "projects/PROJECT_NUMBER/locations/LOCATION/instances/INSTANCE_ID/searchSessions/SEARCH_SESSION_ID/searchedResults/RESULT_ID",
      "resultRow": {
        "eventRecord": {}
      }
    }
  ],
  "totalSize": 10000,
  "columnNames": [],
  "columnSchema": {},
  "nextPageToken": "CAKYASAB"
}

```
To fetch the subsequent page of results, use the returned `nextPageToken` value in the `page_token` query parameter of your next `ListSearchedResults` request. The `resultRow` field contains the actual data.
Continue calling `ListSearchedResults` with the `next_page_token` value from each response. When `next_page_token` returns empty, all results have been retrieved.