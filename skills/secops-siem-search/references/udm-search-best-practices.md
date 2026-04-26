# Source: https://docs.cloud.google.com/chronicle/docs/investigation/udm-search-best-practices

# Search best practices
Supported in:    Google secops   SIEM
This document describes Google's recommended best practices for using the Search feature in Google Security Operations. Searches can require substantial computational resources if they're not carefully constructed. Performance also varies depending on the size and complexity of the data in your Google SecOps instance. Note: For raw log searches, the Search field is limited to 150 characters.
## Use specific filters in queries for maximum speed and performance
The single most effective way to improve search performance is to build queries using specific, optimized Unified Data Model (UDM) fields. These fields are optimized for fast retrieval, ensuring that your searches run quickly and use fewer computational resources.
The following sections list the high-performance UDM fields to use as filters in your queries.
### Principal fields
`principal.asset.hostname` `principal.asset.ip` `principal.asset.mac` `principal.file.md5` `principal.file.sha1` `principal.file.sha256` `principal.hostname` `principal.ip` `principal.mac` `principal.process.file.md5` `principal.process.file.sha1` `principal.process.file.sha256` `principal.process.parent_process.file.md5` `principal.process.parent_process.file.sha1` `principal.process.parent_process.file.sha256` `principal.user.email_addresses` `principal.user.product_object_id` `principal.user.userid` `principal.user.windows_sid`
### Source fields
`source.user.userid` `src.asset.hostname` `src.hostname` `src.ip`
### Target fields
`target.asset.hostname` `target.file.md5` `target.file.sha1` `target.file.sha256` `target.hostname` `target.ip` `target.process.file.md5` `target.process.file.sha1` `target.process.file.sha256` `target.user.email_addresses` `target.user.product_object_id` `target.user.userid` `target.user.windows_sid`
### Additional fields
`about.file.md5` `about.file.sha1` `about.file.sha256` `intermediary.hostname` `intermediary.ip` `network.dns.questions.name` `network.email.from` `network.email.to` `observer.hostname` `observer.ip` `metadata.log_type`  Note: With the exception of `metadata.log_type`, metadata fields are usually not optimized for fast retrieval. You can explore other metadata fields in detail in the following sections.
## Construct effective search queries for performance
Writing optimized queries is key to maximize speed and minimize resource consumption across your security data. All query conditions must strictly adhere to this fundamental structure:
`udm-field operator value`
For example: `principal.hostname = "win-server"` Note: The more focused and precise your query, the faster it runs and the less compute resources it requires.
## Narrow the time range for your search
Because Google SecOps can ingest a large amount of data during a search, minimizing the time range and narrowing the scope of your query can improve search performance.
## Use regular expressions in search query
You can use standard logical and comparison operators when constructing your UDM search queries to build complex expressions:  Logical operators: Use `AND`, `OR`, and `NOT` to combine conditions. `AND` is assumed if you omit an operator between two conditions. Operator precedence: Use parentheses () to override the default order of precedence. There is a maximum limit of 169 logical operators (`OR`, `AND`, `NOT`) that you can use within parentheses. Comparison operators: Depending on the UDM field type (string, integer, timestamp), field operators can include: `=`, `!=`, `>=`, `>`, `<`, `<=`
Alternatively, for efficient searching of a large set of values, you can use the reference lists. Note: Queries that contain multiple regular expressions may take longer to complete.
## Use `nocase` as a search modifier
You can append the `nocase` modifier to a string comparison condition to make the search case-insensitive, which ignores capitalization.
For example, the following search is invalid:
`target.user.userid = "TIM.SMITH" nocase`
## Avoid using regular expressions in enumerated fields
You can't use regular expressions when searching enumerated fields (fields with a range of predefined values) like `metadata.event_type` or `network.ip_protocol`
The following example is an invalid search: `metadata.event_type = /NETWORK_*/`
Whereas, the following example is a valid search: `(metadata.event_type = "NETWORK_CONNECTION"` or `metadata.event_type = "NETWORK_DHCP")` Note: To search for a group of related enumerated values, you must explicitly list each value combined with the `OR` operator.
## Use any and all operators in the Events field
In Search, some UDM fields (like `principal.ip` or `target.file.md5`) are labeled as repeated, because they can hold a list of values or message types within a single event. Repeated fields are always treated with the `any` operator by default (there's no option to specify `all`).
When the `any` operator is used, the predicate is evaluated as `true` if any value in the repeated field satisfies the condition. For example, if you search for `principal.ip != "1.2.3.4"` and events in your search include both `principal.ip = "1.2.3.4"` and `principal.ip = "5.6.7.8"`, a match is generated. This expands your search to include results that match any of the operators instead of matching all of them.
Each element in the repeated field is treated individually. If the repeated field is found in events in the search, the events are evaluated for each element in the field. This can cause unexpected behavior, especially when searching using the `!=` operator.
When using the `any` operator, the predicate is evaluated as `true` if any value in the repeated field satisfies the condition.
## Use Unix epoch time for timestamps
Timestamp fields are matched using Unix epoch time (the total number of seconds that have passed since Thursday, 1 January 1970 00:00:00 UTC).
When searching for a specific timestamp, the following (in epoch time) is valid:
`metadata.ingested_timestamp.seconds = 1660784400`
The following timestamp is invalid:
`metadata.ingested_timestamp = "2022-08-18T01:00:00Z"`
### Exclude fields from filters
The following fields are intentionally excluded from search filters. While they contain crucial metadata, their highly unique values can introduce unnecessary search detail and reduce the overall efficiency and effectiveness of the query engine:  `metadata.id` `metadata.product_log_id` `*.timestamp`