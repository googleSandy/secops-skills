# Source: https://docs.cloud.google.com/chronicle/docs/investigation/data-tables

# Use data tables
Supported in:    Google secops   SIEM
Data tables are multicolumn data constructs that let you input your own data into Google Security Operations. Data tables can act as lookup tables with defined columns and the data stored in rows. You can create or import a data table to your Google SecOps account using the Google SecOps web interface, the data tables API, or by using a Overview of YARA-L 2.0 query.
## Assign scopes to data tables using data RBAC
To use data tables, you need to assign scopes to data tables using data role-based access control (data RBAC). By assigning scopes to a data table, you can control which users and resources can access and utilize it. For more information, see Configure data RBAC for data tables.
## Manage data tables using the Google SecOps web interface
The following sections describe how to manage data tables using the web interface, including how to access data tables, add a new data table, edit its contents, add rows, and how to remove a data table from your account.
### Access your data tables
To access the Data Tables page, do the following:  On the sidebar, select Investigation > Data Tables.
To find a specific data table, at the top of the Data Tables sidebar, enter its name in the Search field.
### Add a new data table
When you add a new data table, you can enter CSV data manually, paste CSV data, or import a CSV or TSV file into the data table.  Note: Data tables don't support tab-separated values except when importing a tab-separated values (TSV) file. When you import a TSV file, Google SecOps converts the tab separators to comma separators within the data table. Data table fields don't support comma (`,`) characters.
The following configurations are permanent and can't be changed after a new data table is saved:  Column headers Data mapping Primary keys Repeated fields Mapping of column names to entity fields
To add a new data table to Google SecOps, do the following:
On the sidebar, select Investigation > Data Tables.
At the top of the Data Tables sidebar, click add Create.
In the Create New Data Table dialog, give the table a name and, optionally, add a description.
Do one of the following:  Enter CSV data manually or paste CSV data into the Text (edit mode) area. Do the following to import data from a CSV or TSV file into the data table:   Click Import File. Go to the file and click Open. The Import File dialog opens. If you selected a TSV file in the previous step, do the following:  From the Separator Type list, select Detect automatically or Tab.  From the Start import at row list, specify the row in the file from which to import the data.   Click Import Data.
Select the Table edit mode and configure the following as needed:  Map data types to data table columns Designate specific columns as key columns Designate specific columns to support repeated fields Map column names to entity fields (optional)
Click Save. The new data table is displayed in the Data Tables sidebar and is ready to accept additional data.
#### Map data types to data table columns
When you add a new data table, you can map data types (string, regular expression, CIDR, or number) to data table columns.
You can map single data fields to a data column, and map repeated data fields to a data column using the web interface or the API, as follows:
In both the web interface and the API, separate the data field values using a pipe (`|`). In the web interface, if any value includes a pipe (`|`), it's treated as a repeated value by default.
For API requests, set `repeated_values` to `true`.
For more information, see Repeated fields.
In the following example, the data table column `Field_value` contains values for multiple fields:   Field_value  Field_name    altostrat.com  FQDN    192.0.2.135  IP    charlie  userid    example  hostname
The preceding table is split into four columns with each column mapped to only one field type before it can be used for any of the data table use cases presented in this document.   FQDN  IP  Userid  Hostname    altostrat.com  192.0.2.135  charlie  example    …  …  …  …
#### Designate key columns
When you add a new data table, you can designate specific columns as key columns.
Marking a column as a key column uniquely identifies the values in that column, prevents data duplication, and improves data discovery for rules and searches. Note: By default, all columns are treated as key columns, unless specified otherwise during data table creation.
#### Designate columns to support repeated fields
When you add a new data table, you can designate specific columns to support repeated fields.
Columns intended to store multi-value fields or repeated fields, must be explicitly designated as repeated when the data table is created.
#### Map column names to entity fields (optional)
When you add a new data table, you can map the column names of the data table to entity fields. Note: Mapping entity fields to columns is optional and used when entity enrichment is performed. For more information, see Enrich entity graph with a data table.
In the following example data table, the `Userid` and `Role` columns are mapped to `entity.user.userid` and `entity.user.attribute.role.name`, respectively:   Userid  (map to entity.user.userid)  Email  Role  (map to entity.user.attribute.role.name)    jack  jack123@gmail.com  administrator    tony  tony123@gmail.com  engineer
You can map a data table column to an entity proto field using the `mapped_column_path` field of the `DataTable` resource.
For columns without a defined entity path, such as `Email` in this example table, you must manually specify a data type. As with reference lists, the supported data types for data tables are `number`, `string`, `regex`, and `cidr`.
You can include both mapped and unmapped columns in a data table by specifying a `join` condition.
Unmapped columns are stored in the `additional` field of the entity the table joins to. These are added as key-value pairs, where the `key` is the column name and the `value` is the corresponding row value.
### Add a new row to a data table
To add a new row, do the following:   On the Details tab, select the Table edit mode.  Right-click an existing row and select Add row above. Enter data for a new row. The first row is treated as a table header. Be sure to match each data item to the appropriate data column and data type. Click Save.  Note: Rows are saved in a random order in the data table.
### Edit a row in a data table
To edit a row, do the following:  Click the field you want to change. The field becomes editable. Make your changes.  Click Save.
### Search data table rows
You can search for specific information within a data table using the web interface. On the Details tab, enter a search string in the search field and click Search. Rows containing your search string are displayed.
### Manage the table row TTL
To manage the time to live (TTL) value for table rows, do the following:
Click Show TTL per row. A TTL column displays, indicating whether each row has expired. If not expired, it shows the remaining time before expiration.
Click the Default row expiration time to display the Update default row expiration dialog and adjust the table row TTL.
Enter a new TTL value in Hours or Days. The minimum value is 1 hour. The maximum value is 365 days.
Click Save.
#### Row-level TTL override behavior
Rows inherit the TTL applied at the table level. You can also set a specific TTL for individual rows, and this row-level TTL takes precedence over the table-level default. When you add a new row, its TTL begins from the time of creation.
### Delete a table row
To delete a row, right-click the row and select Delete row(s).
To delete multiple rows, select each row you want to remove. Then right-click any selected row and choose Delete row(s).
### Remove a data table
To remove a data table, do the following:
Select a data table from the Data Tables list in the sidebar.
Click Delete.
## Manage data tables using the Chronicle API
You can also use the REST resources available in the Chronicle API to manage data tables in Google SecOps. The API can replicate all of the features available in the web interface, and includes some additional features that let you manage data tables with more performance and greater scale.
Here are the data table REST resources:
dataTables
dataTableRows
dataTableOperationErrors
### Example: filter syntax
The following Chronicle API example shows how to use the `filter` syntax to search for `google.com` in data table rows:
```
curl -X GET \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  "https://staging-chronicle.sandbox.googleapis.com/v1alpha/projects/{$PROJECT}/locations/${REGION}/instances/${INSTANCE}/dataTables/${DATA_TABLE_NAME}/dataTableRows?filter=google.com"

```
## Use data tables in Google SecOps
Once you've added data tables to your Google SecOps instance, you can use them to filter, enhance, and enrich your data using YARA-L queries. This document includes numerous examples in YARA-L syntax, which you can incorporate into Google SecOps.
You can use data tables in conjunction with YARA-L queries in both Search and rules.
Data tables can be used in the following ways:
Filter UDM event or entity data using a data table
You can filter UDM telemetry events and entities by comparing them with entries in a data table.
Use a data table as a multicolumn reference list
You can use a data table as a multicolumn reference list. While a reference list can access data in a single dimension, data tables let you access data in multiple dimensions, enabling data filtering.
Join a data table with an event or entity
You can link UDM events to a data table using the equality (`=`) operator for row-based comparisons. This comparison lets you filter the data. A row-based comparison evaluates as `true` only if all conditions in the statement match a single row in the data table.
### Filter UDM event and entity data using a data table
You can filter UDM events and entities by comparing them to entries in a data table. Join the data table with a UDM event or entity using row-based or column-based comparisons.
#### Row-based and column-based comparisons in data tables
Comparison type Key logic Common operators Example syntax When to use     Row-based All conditions must match within the SAME row `=`, `!=`, `>`, `>=`, `<`, `<=` `$e.field = %table.col_a` When the relationship between multiple column values in the same row matters.   Column-based Value must exist ANYWHERE in the column `IN`, `IN regex`, `IN cidr` `$e.field IN %table.col_b` When checking for the presence of a value within a set of values in a single column.
Link UDM events to data tables using Row-based or Column-based comparison methods:
#### Row-based comparison to link UDM events to data tables
To link UDM events to data tables using row-based comparison, use equality operators (`=`, `!=`, `>`, `>=`, `<`, `<=`).
For example: `$<udm_variable>.<field_path> = %<data_table_name>.<column_name>`  If you're using multiple comparison statements, all fields or conditions must match on the same data table row.
To use operators (such as `not`, `!=`, `>`, `>=`, `<`, `<=`) in your query, you must include at least one `join` condition between UDM fields and data table rows.
Google SecOps treats any rule with a data table `join` as a multi-event rule, which requires a `match` section in the rule definition.
To filter data by matching values from UDM events against rows in the data table, consider the following join syntax:
Correct join syntax:
Row-based "combination exclusion" requires, for example, a `left outer` join and a `where` clause checking for `nulls`.
Incorrect join syntax:
Don't wrap `NOT` around multiple row-based equality conditions. This syntax does not achieve an "exclude if this combination is found" effect.
For example, don't use this syntax: `NOT (field1 = %table.col1 AND field2 = %table.col2)`
This is because the match is still applied row by row. If any row fails the inner combined condition, the `NOT` causes that row's evaluation to be `true`, potentially including the event rather than excluding it.
To use a data table column of type `CIDR` or `regex` for row-based comparison, use the following syntax:
```
net.ip_in_range_cidr($e.principal.ip, %<data_table_name>.<column_name>)

  re.regex($e.principal.hostname, %<data_table_name>.<column_name>)

```
#### Column-based comparison to link UDM events to data tables
To link UDM events to data tables using column-based comparison, use the `in` keyword.
For example: `$<udm_variable>.<field_path> in %<data_table_name>.<column_name>`
To filter out events where the field value exists in the specified column (for example, a blocklist or allowlist), use this syntax: `NOT (... IN %table.column)`
For example: `not ($evt_username in %my_data_table.username)`
To use a data table column of type `CIDR` or `regex` for column-based comparison, use the following syntax:
```
$e.principal.ip in cidr %cidr_data_table.column_name

$e.principal.hostname in regex %regex_data_table.column_name

```
When comparing columns in data tables that are CIDR or regular expression data types, the `cidr` and `regex` keywords are optional.
You can also use the `not` operator with data tables.
The following example query filters out entries where the IP addresses (`$e.principal.ip`) don't match any of the CIDR ranges listed in the `benign_ip` column in `cidr_data_table`:
```
not $e.principal.ip in %data_table.benign_ip

```
### Use a data table as a multicolumn reference list
You can use a data table as a multicolumn reference list. Although a reference list can access data in a single dimension (one column), data tables support multiple columns, letting you filter and access data across several dimensions.
You can link UDM events to a data table using the `in` keyword for column-based comparison, letting you match values in a specific UDM field against values in a single column of the data table.
In the following example, the `badApps` data table contains two columns: `hostname` and `ip`. The query matches both values (value based on UDM field and value based on the data table, both of string data types) independently.
Rule example:
```
rule udm_in_data_table {
meta:
  description = "Use data table as multicolumn reference list"
events:
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.security_result.action = "ALLOW"
  $e.target.asset.asset_id = $assetid

  // Event hostname matches at least one value in table column hostname.
  $e.target.hostname in %badApps.hostname

  // Event IP matches at least one value in table column ip.
  $e.target.ip in %badApps.ip

match:
  $assetid over 1h

condition:
  $e
}

```
Search example:
```
events:
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.security_result.action = "ALLOW"
  $e.target.asset.asset_id = $assetid

  // Event hostname matches at least one value in table column hostname.
  $e.target.hostname in %badApps.hostname

  // Event IP matches at least one value in table column ip.
  $e.target.ip in %badApps.ip

```
### Row-based joins between a data table and a UDM event or entity
You can link UDM events to a data table using equality and comparison operators (`=, !=, >, >=, <, <=`) to perform row-based comparisons. This approach lets you filter data by matching values from UDM events against rows in the data table. If you're using multiple comparisons statements, all fields or conditions must match on the same data table row.
You must include at least one `join` condition between UDM fields and data table rows to use operators (such as `not, !=, >, >=, <, <=`) in your query. Google SecOps treats any rule with a data table `join` as a multi-event rule, which requires a corresponding `match` section in the rule definition.
When a join occurs, the linked data table rows are visible in Search. For more information, see View data table rows in Search.
Placeholders are supported for data tables in the `event` section of a query, but they must be connected to a UDM event or a UDM entity.
The following example uses a data table column of `string` type.
This YARA-L query example checks whether a user login event matches a row in the `example_table`.
One condition is that the `user ID` exists in the `example_table`.
Both conditions must match on the same row in the `example_table` for the rule to trigger.
```
// Check if a user exists in a data table and that the user is active for all user login events.

```
Rule example:
```
// Check if user exists in a data table and is active in all user login events.
rule udm_join_data_table {

meta:
  description = "Join data table with UDM event"

events:
  $e.metadata.event_type = "USER_LOGIN"
  $e.security_result.action = "ALLOW"
  $e.principal.user.userid = $userid

// Event must match at least 1 row in the data table 
// where the uid in the data table row is the userid on the event 
// and the active date in the same data table row is before the event timestamp.
%example_table.uid = $userid
$e.principal.hostname = %example_table.hostname

match:
  $userid over 1h

condition:
  $e
}

```
Search example:
```
events:
$e.metadata.event_type = "USER_LOGIN"
$e.security_result.action = "ALLOW"
$e.principal.user.userid = $userid

// Event must match at least 1 row in the data table 
// where the uid in the data table row is the userid on the event 
// and the active date in the same data table row is before the event timestamp

%example_table.uid = $userid
$e.principal.hostname = %example_table.hostname

```
The following example illustrates how a data table and UDM event data work together.
Based on the logic in the preceding YARA-L query, a user with `user ID 32452` surfaces in the detection as the user's `hostname` from the system, and matches the `hostname` in the data table.
Data table    uid  title  hostname    32452  HR  host1    64452  Finance  host2   46364  IT  host3
UDM event table    principal  metadata  security_result  principal    32452  USER_LOGIN  ALLOW  host1    64589  USER_LOGIN  ALLOW  host9    87352  USER_LOGIN  ALLOW  host4
## Write results from YARA-L queries to data tables
You can write the results from YARA-L queries to a data table. Using this feature, you can create data tables from your Google SecOps data and use those tables to filter and enhance other data.
You can use the YARA-L query write syntax for the following:
Define YARA-L syntax for writing query results to data tables.
Use data tables for threat intelligence, incident response, and other security use cases.
Data should conform to YARA-L syntax and conventions.
### Write detections and alerts to data tables using YARA-L
You can use a YARA-L query to send detections and alerts to data tables. Note: This functionality is supported only in rules and search.
Using the write_row function, you can overwrite a data table row with the matching key in the data table using the results from a rule. If the key is not found in the table, add a new row instead.
Specify the write_row function in the export section of a YARA-L query. Writing data to the data table must be the final action of the query. This results in the outcome variables being written to the data table.
```
export:
  %<data_table_name>.write_row(
  data_table_column_x_name: <value>,
  data_table_column_y_name: <value>,
  ...,
  ...,
  data_table_column_z_name: <value>
)
// depending on the key column(s), the rows will be updated for existing keys 
and appended for new keys

```
Example: Export search results to data table
```
events:
  $e.metadata.event_type = "USER_LOGIN"
  $e.security_result.action = "ALLOW"

outcome:
  $user = $e.principal.user.userid
  $ip = $e.target.ip[0] // Assuming target.ip is an array
  $timestamp = $e.metadata.event_timestamp.seconds

export:
  // Write to the data table named 'successful_logins'
  %successful_logins.write_row(
    user: $user,          // Maps $user variable to 'user' column
    ip: $ip,              // Maps $ip variable to 'ip' column
    first_seen: $timestamp // Maps $timestamp variable to 'first_seen' column
  )

```
### Modify a data table using YARA-L
The following shows how to modify a data table using YARA-L:
TableName: `ip_user_domain_table` (key columns for the primary key are defined at creation)   IP address  employee_id*  domain    192.0.2.10  Dana  altostrat.com    192.0.2.20  Quinn  altostrat.com    192.0.2.30  Lee  cymbalgroup.com
* indicates the primary key. Note: The primary key can be a combination of multiple columns, though it is a single column in this example.
The following query captures unique combinations of `principal.ip`, `principal.user.employee_id`, and `target.domain`. It filters the results based on the prevalence of the `target.domain`:
```
events:
  $e.principal.ip = $principal_ip
  $e.principal.user.employee_id = $principal_user_employee_id
  $e.target.domain.name = $target_domain
  $e.target.domain.prevalence.day_count < 5

// To run this query as a rule, add Condition Section here 
// condition:$e

```
Query results:   ip  empid  domain    192.0.2.10  Dana  altostrat.com    192.0.2.30  Lee  examplepetstore.com    192.0.2.20  Quinn  altostrat.com
### Example: Use write_row to write query output to a data table
Rule example:
```
  rule udm_write_data_table {
  meta:
      description = "Writeto data table"
  events:
    $e.principal.user.employee_id = $principal_user_employee_id
    $e.target.domain.name = $target_domain
    $e.target.domain.prevalence.day_count < 5

  outcome:
    $hostname = $target_domain
    $principal_emp_id = $principal_user_employee_id
  
  condition:
    $e

  export:
    %ips_with_hostnames.write_row(
        employeeid:$principal_emp_id,
        hostname:$hostname
    )
  }

```
Search example:
```
events:
  $e.principal.user.employee_id = $principal_user_employee_id
  $e.target.domain.name = $target_domain
  $e.target.domain.prevalence.day_count < 5

outcome:
  $hostname = $target_domain
  $principal_emp_id = $principal_user_employee_id

export:
  %ips_with_hostnames.write_row(
    employeeid:$principal_emp_id,
    hostname:$hostname
  )

```
### Example: Understanding write_row
In the following example, `user` and `ip` are used as primary keys. Each detection that persists in the detections table results in one evaluation of the function call in the export section of the query.
Rule example:
```
  rule udm_write_data_table {
  meta:
    description = "Write data table"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    all $e.security_result.action != "BLOCK"
    all $e.security_result.action != "UNKNOWN_ACTION"

    $user = $e.principal.user.userid
    $ip = $e.target.ip
    $ts = $e.metadata.event_timestamp.seconds

  match:
    $user, $ip over 1h

  outcome:
    $first_seen = min($ts)

  condition:
    $e

  export:
    %successful_logins.write_row(user:$user, ip:$ip)
  }

```
Search example:
```
events:
  $e.metadata.event_type = "USER_LOGIN"
  all $e.security_result.action != "BLOCK"
  all $e.security_result.action != "UNKNOWN_ACTION"

  $ts = $e.metadata.event_timestamp.seconds

outcome:
  $user = $e.principal.user.userid
  $ip = $e.target.ip[0]

export:
  %successful_logins.write_row(user:$user, ip:$ip)

```
Here is the event data:
```
metadata: {
  event_type: USER_LOGIN
  event_timestamp: { seconds: 1283299200 }
}
principal: {
  user: {
    userid: "charlie"
  }
}
target: {
  ip: ["192.0.2.135", "192.0.2.136"]
}
security_result: {
  action: ALLOW
}

```
The following detections are returned when this query is executed as a rule:   Detection ID  Match $user  Match $ip    0  charlie  192.0.2.135    1  charlie  192.0.2.136
The data table contains the following:   user  ip    charlie  192.0.2.135    charlie  192.0.2.136     Note: If you click Run test in the Rules Editor to check a rule, the example data doesn't persist in the data table.
The following search query illustrates the support offered in Search for writing scalar values to data tables. Note: This is not supported in rules.
```
events:
  $e.metadata.event_type = "NETWORK_CONNECTION"

export:
  %summary_table.write_row(col_name: $e.metadata.product_name, Vendor_name: $e.metadata.vendor_name)

```
## Enrich entity graph with a data table
You can use data tables to add, remove, or replace the entities presented in an entity graph from rules. Use functions in the rule `setup` section to indicate how the data table should be merged with, appended to, or used to remove entities from entity events referenced in the `events` section. Note: This is not supported with Search.
You can use the following rule template to modify an entity graph:
```
rule entity_graph_template {

  meta:
    ...

  setup:
    // import the data table into entity graph
    <enrichment_keyword> <join_condition>

  events:
    ...

  match:
    ...

  condition:
    ...
}

```
You can use the following YARA-L 2.0 functions to enhance entity graph with a data table:
`graph_override`: Overwrite the rows in the entity graph that match the join condition with data from the data table.
For example: `[graph_override](?tab=t.0#heading=h.v0fps7eke1if)`
`graph_append`: Append the rows from the data table to the rows in the entity graph. The `graph_append` operation requires an array that includes a data table variable and an entity event variable rather than a join condition.
In the following example, `$g1` is the entity graph variable and `example_table` is the data table: `graph_append [$g1, %example_table]`
For the `append` function, data tables should include the following columns to validate the entity:
`start_time` (mapped to `metadata.interval.start_time.seconds`)
`end_time` (mapped to `metadata.interval.end_time.seconds`)
Data table columns cannot be mapped to metadata fields using the web interface. For `append` use cases, data tables need to be created using Chronicle API (https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.dataTables/create)
`graph_exclude`: Remove the rows in the entity graph that match the `join` condition.
For example: `[graph_exclude](?tab=t.0#heading=h.o0qbb5paki6g)`
The join condition must be an equality expression between the data table column and the entity graph field. For the `graph_override` and `graph_exclude` functions, the syntax to access a data table is as follows:
`<data_table_name>.<column_name>`
Any filter specified for the `<entity_variable>` in the event section is applied after its enhancement with the data table.
After the entity in the entity graph is enriched with the entity in the data table, the entity variable in the entity graph must be joined to the UDM entity.
### Override entity graph with data from data table
With the `graph_override` function, fields present in both the entity graph and the data table are replaced with fields from the data table. Fields present in the entity graph and not in the data table remain the same. Fields not present in the entity graph but present in the data table are included.
Only those columns of the data table that are mapped override the columns of the entity graph. The columns that are unmapped are added to the `additional` field of the entity graph on which the data table is joined.
#### Example: Match on single join
In the following example, the rows in the entity graph that match the join condition between the data table column and the entity graph field (`$g1.graph.entity.ip = %example_table.my_ip`) are overridden by the data table.
```
rule rule_override {
  meta:
    description = "Override entity context with data table before joining with UDM event"

  setup:
    //Rows in the entity graph that match the join condition are overridden by the data table
    graph_override ($g1.graph.entity.ip = %example_table.my_ip)

  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $e.security_result.action = "ALLOW"

    // Filter will be applied after graph is overridden by data table
    $g1.graph.entity.hostname = "ftp01"

    // Accessing unmapped columns
    $g1.graph.additional.fields["Owner"] = "alice"

    // Joining the UDM event with the enriched entity graph
    $e.target.ip = $iocip
    $g1.graph.entity.ip = $iocip

  match:
    $iocip over 1h

  condition:
    $e and $g1
}

```
To use an unmapped column (say "Owner") of the data table, then an equivalent statement for `$g1.graph.entity.owner = "alice" is $g1.graph.additional.fields["Owner"] = "alice"`. This is because all unmapped columns of the data table go into the `additional` field of the entity graph `($g1)`.
The following tables illustrate an override operation where rows in the entity graph are enriched when the IP field in the data table matches the IP field in the entity graph.   Existing entity graph    Hostname  IP  MAC    ftp01  10.1.1.4  …:01    www01  10.1.1.5  …:02      Data table    Hostname  IP  MAC  Owner    ftp01  10.1.1.4  …:bb  alice    h1  10.1.1.6  …:cc  bob    h2  10.1.1.7  …:dd  chris    h3  10.1.1.4  …:ee  doug
Enriched entity graph    Hostname  IP  MAC  Owner    ftp01  10.1.1.4  …:bb  alice    www01  10.1.1.5  …:02      h3  10.1.1.4  …:ee  doug
#### Example: Match on multiple joins
In the following example, the rows in the entity graph that match the multiple join conditions (`$g1.graph.entity.ip = %example_table.my_ip` and `$g1.graph.entity.hostname = %example_table.my_hostname`) are overridden by the data table.
```
rule rule_override {
meta:
    description = "Override Entity context with Data Table before joining with UDM event"
setup:
  // example with more than one condition
  graph_override ($g1.graph.entity.ip = %example_table.my_ip and
  $g1.graph.entity.hostname = %example_table.my_hostname) 
events:
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.security_result.action = "ALLOW"

  // Filter will be applied after graph is overridden by data table
  $g1.graph.entity.hostname = "ftp01"

  // joining the UDM event with the enriched entity graph
  $e.target.ip = $iocip
  $g1.graph.entity.ip = $iocip

match:
  $iocip over 1h

condition:
  $e and $g1
}

```
The following tables illustrate an override operation in which the rows of the entity graph are enriched when both the IP field and the hostname field in the data table match the IP field and the hostname field in the entity graph.   Existing entity graph    Hostname  IP  MAC    ftp01  10.1.1.4  …:01    www01  10.1.1.5  …:02      Data table    Hostname  IP  MAC  Owner    ftp01  10.1.1.4  …:bb  alice    h1  10.1.1.5  …:cc  bob    h2  10.1.1.6  …:dd  chris    h3  10.1.1.4  …:ee  doug      Enriched entity graph    Hostname  IP  MAC  Owner    ftp01  10.1.1.4  …:bb  alice    www01  10.1.1.5  …:02
### Append data from the data table to entity graph
With the `graph_append` function, no join condition is required.
In the following example, all rows in the data table are appended to the rows in the entity graph. Note: There is no deduplication of the rows appended to the entity graph. This means that if a row is present in both the entity graph and the data table, then both rows are present in the enriched entity graph.
```
rule rule_append {
meta:
  description = "Data table append entity"
   
setup:
  graph_append [$g1, %example_table]

events:
    // filter UDM events
  $e.metadata.event_type = "NETWORK_CONNECTION"
  $e.security_result.action = "ALLOW"

  // Join the filtered UDM events with the enriched graph
  $e.target.ip = $iocip
  $g1.graph.entity.ip = $iocip

match:
  $iocip over 1h

condition:
  $e and $g1
}

```
The following example table illustrates an append operation where the rows of the data table are appended to the rows in the entity graph:   Existing entity graph    Hostname  IP  MAC    ftp01  10.1.1.4  …:01    www01  10.1.1.5  …:02      Data table    IP  MAC  Owner    10.1.1.4  …:01  alice    10.1.1.6  …:cc  bob    10.1.1.7  …:dd  chris    10.1.1.4  …:ee  doug      Enriched entity graph    Hostname  IP  MAC  Owner    ftp01  10.1.1.4  …:01      www01  10.1.1.5  …:02        10.1.1.4  …:bb  alice      10.1.1.6  …:cc  bob      10.1.1.7  …:dd  chris      10.1.1.4  …:ee  doug
### Use graph_exclude to remove rows from entity graph
With the `graph_exclude` function, rows in the entity graph that match the join condition are removed from the entity graph.
In the following example, all rows in the entity graph that match the given join condition (between the data table column and the entity graph field) are removed. No rows from the data table are added to the entity graph.
```
rule rule_exclude {

    meta:
    setup:
      graph_exclude ($g1.graph.entity.ip = %example_table.ip)

    events:
        $e.metadata.event_type = "NETWORK_CONNECTION"
        $e.security_result.action = "ALLOW"
        $e.target.ip = $iocip
        $g1.graph.entity.ip = $iocip

    match:
        $iocip over 1h

    condition:
        $e and $g1
}

```
The following tables illustrate an exclude operation in which the rows of the entity graph that match the IP field of the data table are removed:   Existing entity graph    Hostname  IP  MAC    ftp01  10.1.1.4  …:01    www01  10.1.1.5  …:02      Data table    IP  MAC  Owner    10.1.1.4  …:bb  alice    10.1.1.6  …:cc  bob    10.1.1.7  …:dd  chris      Enriched entity graph    Hostname  IP  MAC    www01  10.1.1.5  …:02
## Limitations
Maximum number of data tables for a Google SecOps account: 1,000.
Data tables support only CSV data. Data tables support tab-separated values only when adding a new data table and importing a tab-separated values (TSV) file.
Data table fields don't support comma (`,`) characters.
The limits on the number of `in` statements when referencing a reference list in a query also apply to `in` statements in a data table.
Maximum number of `in` statements in a query for `String` and `Number` data type columns: 10.
Maximum number of `in` statements with regular expression operators: 5.
Maximum number of `in` statements with CIDR operators: 5.
Maximum number of `= (JOIN)` statements: 10.
Maximum columns per data table: 1,000.
Maximum rows per data table: 10 million.
Maximum display limit in web page for data table rows in text and table editor view: 10,000 rows.
Maximum data volume in a data table: 10 GB.
Placeholders aren't allowed in the setup section.
Unmapped columns of a data table with data type set to `string` can only be joined with string fields of UDM event or UDM entity.
Use only unmapped columns in a data table with a data type set to `cidr` or `regex` for CIDR or regular expression.
Data table lookups: Regular expression wildcards aren't supported and search terms are limited to 100 characters.
### Limitations for data table joins in rules
The following limitations apply to data table joins in rules.
Fetching all event samples for detections isn't supported when using data table joins with events.
Unlike entities and UDM, data tables don't support placeholders. This leads to the following limitations:
You can't apply one set of filters to a data table and join it with a UDM entity.
You can't apply a different set of filters to the same data table while joining it with another UDM placeholder.
For example, a data table named `dt` with three columns: `my_hostname`, `org`, and `my_email` and with the following rule:
```
events:
  $e1.principal.hostname =  %dt.my_hostname
  %dt.org ="hr"

  $e2.principal.email =  %dt.my_email
  %dt.org !="hr"

```
All filters on a data table are applied first, and then the filtered rows from the data table are joined with UDM. In this case, the contradictory filters (`%dt.org ="hr" and %dt.org !="hr"`) on the `dt` table result in an empty data table, which is then joined with both `e1` and `e2`.
### Limitations using data tables with rules
The following limitations apply to data tables when used with rules.
#### Limitations for run frequency
Real-time run frequency isn't supported for rules with data tables.
#### Limitations for output to data tables
`any` and `all` modifiers aren't supported for repeated field columns in data tables.
Array indexing isn't supported for repeated fields columns in data tables.
You can only export outcome variables to a data table. You can't export event paths or data table columns directly.
Column lists must include the primary key columns for data tables.
You can have a maximum of 20 outcomes.
If a data table doesn't exist, a new table is created with the default `string` data type for all columns, following the order specified.
A maximum of five rules can write to a data table concurrently.
There's no guarantee that a producer rule can add rows to a data table before a consumer rule for that data table starts.
A single rule has a limit on the number of outcome rows. A maximum 10,000-row limit applies over the result and persisted data and to data tables.
When you update a row, the new values for all non-key columns replace the old ones. Any updates, including adding a new row, take approximately five minutes to become available for querying.
#### Limitations for entity enrichment from data tables
You can apply only one enrichment operation (either `override`, `append`, or `exclude`) to a single entity graph variable.
Each enrichment operation can use only one data table.
You can define a maximum of two enrichment operations of any type in the `setup` section of a YARA-L rule.
In the following example, an `override` operation is applied to the entity graph variable `$g1` and an `append` operation is applied to the entity graph variable `$g2`.
```
    setup:
    graph_override($g1.graph.entity.user.userid = %table1.myids)
    graph_append [$g2, %table1]

```
In the preceding example, the same data table (`table1`) is used to enhance different entity graphs. You can also use different data tables to enhance the different entity graphs, as follows:
```
    setup:
    graph_override($g1.graph.entity.user.userid = %table1.myids)
    graph_append [$g2, %table2]

```
### Limitations using data tables with Search
The following limitations apply to data tables when used with Search:
You can't run search queries on data tables using the Chronicle API. Queries are only supported through the web interface.
A single query execution can output a maximum of 1 million rows to a data table or 1 GB, whichever limit comes first.
Search output to a data table skips event rows if they exceed 5 MB.
Entity enrichment is not supported with Search.
Data tables are not supported for customer-managed encryption keys (CMEK) users.
Writes are limited to 6 per minute per customer.
API support is not available for Search-related data table operations.
Data table and data table joins are only supported with UDM events, and not with entities.
Supported: `%datatable1.column1 = %datatable2.column1`
Not supported: `graph.entity.hostname = %sample.test`
You can't include a `match` variable in the `export` section of a statistics query.
For example, the following is not supported:
```
  match:
      principal.hostname
  export:
      %sample.write_row(
      row: principal.hostname
    )

```