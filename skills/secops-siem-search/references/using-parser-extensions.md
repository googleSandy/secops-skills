# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/using-parser-extensions

# Parser extensions
Supported in:    Google secops   SIEM
This document explains how to create parser extensions to extract fields from raw log data and map them to destination UDM (Unified Data Model) fields within the Google Security Operations platform.
The document outlines the parser extension creation process:  Create parser extensions. Prerequisites and limitations. Identify source fields in the raw log data. Select the appropriate destination UDM fields.
Choose the appropriate parser extension definition approach:
Defining a parser extension includes designing the parsing logic to filter raw log data, transforming the data, and mapping it to destination UDM fields. Google SecOps provides two approaches to create parser extensions:  Create parser extensions using the no-code (Map data fields) approach. Create parser extensions using the code snippet approach.
Illustrative parser extension creation examples for various log formats and scenarios. For example, no-code examples using JSON, and code snippets for complex logic or non-JSON formats (CSV, XML, Syslog).
## Create parser extensions
Parser extensions provide a flexible way to extend the capabilities of existing default (and custom) parsers. Parser extensions provide a flexible way to extend the capabilities of existing default (or custom) parsers without replacing them. The extensions let you customize the parser pipeline by adding new parsing logic, extracting and transforming fields, and updating or removing UDM field mappings.
A parser extension is not the same as a custom parser. You can create a custom parser for log type that does not have a default parser, or to opt out of parser updates.
### Parser extraction and normalization process
Google SecOps receives original log data as raw logs. Default (and custom) parsers extract and normalize core log fields into structured UDM fields in UDM records. This represents only a subset of the original raw log data. You can define parser extensions to extract log values not handled by default parsers. Once activated, parser extensions become part of the Google SecOps data extraction and normalization process.
### Define new parser extensions
Default parsers contain predefined sets of mapping instructions that specify how to extract, transform, and normalize core security values. You can create new parser extensions by defining mapping instructions using either the no-code (Map data fields) approach or the code snippet approach:
No-code approach
The no-code approach is most suitable for simple extractions from raw logs in native JSON, XML, or CSV format. It lets you specify raw log source fields and map corresponding destination UDM fields.
For example, to extract JSON log data with up to 10 fields, using simple equality comparisons.
Code snippet approach
The code snippet approach lets you define instructions to extract and transform values from the raw log and assign them to UDM fields. Code snippets use the same Logstash-like syntax as the default (or custom) parser.
This approach is applicable to all supported log formats. It is best for these scenarios:  Complex data extractions or complex logic. Unstructured data requiring Grok-based parsers. Non-JSON formats such as CSV and XML.
Code snippets use functions to extract specific data from the raw log data. For example, Grok, JSON, KV, and XML.
In most cases it's best to use the data mapping approach that was used in the default (or custom) parser.
### Merge newly extracted values into UDM fields
Once activated, parser extensions merge newly extracted values into designated UDM fields in the corresponding UDM record according to predefined merge principles. For example:
Overwrite existing values: Extracted values overwrite existing values in the destination UDM fields.
The only exception is repeated fields, where you can configure the parser extension to append new values when writing data to a repeated field in the UDM record.
Parser extension takes precedence: Data mapping instructions in a parser extension take precedence over those in the default (or custom) parser for that log type. If there is a conflict in mapping instructions, the parser extension will overwrite the value set by the default.
For example, if the default parser maps a raw log field to the `event.metadata.description` UDM field and the parser extension maps a different raw log field to that same UDM field, the parser extension overwrites the value set by the default parser.
### Limitations
One parser extension per log type: You can create only one parser extension per log type. Only one data mapping instruction approach: You can build a parser extension using either the no-code or the code snippet approach, but not both approaches together. Log samples for validation: Log samples from the last 30 days are required to validate a UDM parser extension. For details see, Ensure there is an active parser for the log type. Base parser errors: Base parser errors are not identifiable or fixable within parser extensions. Repeated fields in code snippets: Use caution when replacing entire repeated objects in code snippets to avoid unintended data loss. For details see More about the repeated fields selector. Repeated fields in no-code approach: You can only append values to repeated objects using this approach. `Additional.fields` is interpreted as a set of key-value pairs, not a repeated field: Consequently, you can seamlessly combine both the parser's UDM mappings and the extension's UDM outputs by adding their respective key-values to the set. Disambiguated events: Parser extensions cannot handle logs with multiple unique events in a single record, for example, Google Drive array. XML and no-code: No-code mode isn't supported for XML. Use the code snippet method instead. No retroactive data: You cannot parse raw log data retroactively. Reserved keywords with the no-code approach: If the logs contain any of the following reserved keywords, use the code snippet approach instead of the no-code approach:  `collectionTimestamp` `createTimestamp` `enableCbnForLoop` `event` `filename` `message` `namespace` `output` `onErrorCount` `timestamp` `timezone`  Remove existing mappings: You can remove existing UDM field mappings using only the code snippet approach. No removing of mapping of a hostname UDM field using an extension: You can't unset (remove) a mapping of a hostname UDM field (for example, `principal.hostname`) using an extension.
### Parser concepts
The following documents explain important parser concepts:  Overview of the Unified Data Model Overview of log parsing Parser syntax reference
### Prerequisites
Prerequisites for parser extension creation:  There must be an active default (or custom) parser for the log type. Google SecOps must be able to ingest and normalize the raw logs using a default (or custom) parser. Make sure the active default (or custom) parser for your target log type has ingested raw log data within the last 30 days. This data should contain a sample of the fields you intend to extract or use to filter the log records. It will be used to validate your new data mapping instructions.
## Get started
Before you create a parser extension, do the following:
Verify the prerequisites:
Ensure there is an active parser for the log type. If it doesn't have a parser yet, create a custom parser.
Identify the fields to extract from the raw logs:
Identify the fields you want to extract from the raw logs.
Select appropriate UDM fields:
Select the appropriate corresponding UDM fields to map the extracted raw log fields.
Choose a parser extension definition approach:
Choose either of the two extension approaches (data mapping approaches) to create the parser extension.
### Verify the prerequisites
Ensure there is an active parser for the log type you intend to extend, as described in the following sections:
#### Ensure there is an active parser for the log type
Make sure there is an active default (or custom) parser for the log type you intend to extend.
Search for your log type in these lists:
Supported log types with a default parser.  If there is a default parser for the log type, ensure the parser is active. If there is no default parser for the log type, ensure there is a custom parser for the log type.
Supported log types without a default parser.  If there is no default parser for the log type, ensure there is a custom parser for the log type.
##### Ensure there is a custom parser for the log type
To ensure there is a custom parser for a log type:  In the navigation bar, select SIEM Settings > Parsers.
Search the Parsers table for the log type you want to extend.  If that log type doesn't have a default or custom parser yet, click CREATE PARSER, and follow the steps in, Create a custom parser based on mapping instructions. If that log type already has a custom parser, ensure the parser is active.
#### Ensure the parser is active for the log type
To check if a parser is active for a log type, perform the following steps:  In the navigation bar, select SIEM Settings > Parsers.
Search the Parsers table for the log type you want to extend.
If the parser for the log type is not active, activate it:  For default parsers see, Manage prebuilt parser updates. For custom parsers see, Manage custom parser updates.
### Identify the fields to extract from the raw logs
Analyze the raw log you want to extract data from to identify the fields not extracted by the default (or custom) parser. Pay attention to how the default (or custom) parser extracts raw log fields and maps them to their corresponding UDM fields.
To identify the specific fields you want to extract from the raw logs, you can use the search tools to identify the fields:
To access the search tool, go to Investigation > SIEM Search. Type raw= before your search query. For details, see Conduct a raw log search.
To access the legacy search tool, click Go to Legacy search at the top of the SIEM Search page. For details, see Search raw logs using raw log scan.
For details about searching in the raw logs, see:  Regular expressions Sample regular expressions to search for Windows logs
### Select appropriate UDM Fields
Now that you've identified the specific target fields to be extracted, you can match them to corresponding destination UDM fields. Establish a clear mapping between the raw log source fields and their destination UDM fields. You can map data to any UDM field that supports the standard data types or repeated fields.
#### Choose the correct UDM field
The following resources can help simplify the process:  Familiarize yourself with the main UDM concepts Understand the data mapping used by the existing parser Use the UDM Lookup tool to find potential UDM fields that match your source fields. The Important UDM fields for parser data mapping guide includes a summary and explanation of the UDM schema's most frequently used fields. The Unified Data Model field list contains a list of all UDM fields and their descriptions. Repeated fields are identified by the "repeated" label in the lists. Important UDM considerations to avoid errors
#### Familiarize yourself with the main UDM concepts
Logical objects: Event and Entity
The UDM schema describes all available attributes that store data. Each UDM record describes an Event or Entity. Data is stored in different fields depending on whether the record describes an Event or an Entity.  A UDM Event object stores data about the action that occurred in the environment. The original event log describes the action as it was recorded by the device, such as firewall or web proxy. UDM Entity objects store data about the participants or entities involved in the UDM event, such as assets, users, or resources in your environment.
Structure of a UDM Event
Structure of a UDM Entity
UDM Nouns: A noun represents a participant or entity in a UDM event. A noun could be, for example, the device or user that performs the activity described in the event. A noun could also be, the device or user that is the target of the activity described in the event.    UDM Noun Description     `principal` The entity responsible for initiating the action described in the event.   `target` The entity that is the recipient or object of the action. In a firewall connection, the machine receiving the connection would be the target.   `src` A source entity acted upon by the principal. For example, if a user copies a file from one machine to another, the file and the machine where it originated would be represented as the src.   `intermediary` Any entity that acts as a go-between in the event, such as a proxy server. They can influence the action, like blocking or altering a request.   `observer` An entity that monitors and reports on the event but doesn't directly interact with the traffic. Examples include network intrusion detection systems or security information and event management systems.   `about` Any other entities involved in the event that don't fit the previous categories. For example, email attachments or loaded DLLs during a process launch.
In practice, the principal and target Noun objects are those most frequently utilized. It is also important to note that the preceding descriptions constitute the recommended usage of Nouns. Actual usage may vary based on the implementation of a default or custom base parser.
#### Understand the data mapping used by the existing parser
It is recommended to understand the existing data mapping used by the default (or custom) parser, between the raw log source fields to their destination UDM fields.
To view the data mapping between raw log source fields and destination UDM fields used in the existing default (or custom) parser:  In the navigation bar, select SIEM Settings > Parsers. Search the Parsers table for the log type you want to extend.
Navigate to that row, then click the more_vert Menu > View.
The Parser Code tab displays the data mapping between raw log source fields and destination UDM fields used in the existing default (or custom) parser.
#### Use the UDM Lookup tool
Use the UDM Lookup tool to help identify UDM fields that match the raw log source fields.
Google SecOps provides the UDM Lookup tool to help you quickly find destination UDM fields. To access the UDM Lookup tool, go to Investigation > SIEM Search.
See these topics for details of how to use the UDM Lookup tool:  Find a UDM field Enter a UDM search Set a time filter on the search Example UDM searches Generate UDM Search queries with Gemini
##### UDM Lookup tool example
For example, if you have a source field in the raw log named "packets", use the UDM Lookup tool to find potential destination UDM fields with "packets" in their name:
Go to Investigation > SIEM Search.
In the SIEM Search page, enter "packets" in the Look up UDM fields by value field, then click UDM Lookup.
The UDM Lookup dialog opens. The search tool matches UDM fields either by field name or field value:  Lookup by field name - Matches the text string you enter to field names containing that text. Lookup by field value - Matches the value you enter to fields that contain that value in their stored log data.
In the UDM Lookup dialog, select UDM Fields.
The search function will display a list of potential UDM fields containing the text "packets" in their UDM field names.
Click each row one by one to view the description of each UDM field.
#### Important UDM considerations to avoid errors
Similar-looking fields: UDM's hierarchical structure can lead to fields with similar names. Refer to default parsers for guidance. For details see, Understand the data mapping used by the existing parser. Arbitrary field mapping: Use the `additional` object for data that doesn't directly map to a UDM field. For details see, Arbitrary field mapping into UDM. Repeated fields: Be cautious when working with repeated fields in code snippets. Replacing an entire object might overwrite the original data. Using the no-code approach offers more control over repeated fields. For details see, More about the repeated fields selector. Mandatory UDM fields for UDM event types: When assigning a UDM `metadata.event_type` field to a UDM record, each `event_type` requires a different set of related fields to be present in the UDM record. For details see, More about assigning UDM `metadata.event_type` fields. Base parser issues: Parser extensions cannot fix errors from the base parser. The base parser is the default (or custom) parser that created the UDM record. Consider options such as enhancing the parser extension, modifying the base parser, or pre-filtering logs.
##### Arbitrary field mapping into UDM
When you can't find a suitable standard UDM field to store your data, use the `additional` object to store the data as a custom key-value pair. This lets you store valuable information in the UDM record, even if it doesn't have a matching UDM field.
### Choose a parser extension definition approach
Before you choose a parser extension definition approach, you must have worked through these sections:  Create parser extensions Get started
The next steps are to open the Parser extensions page and select the extension approach to use to define the parser extension:
#### Open the Parser extensions page
The Parser extensions page lets you define the new parser extension.
You can open the Parser extensions page in the following ways, from the Settings menu, from a Raw log search, or from a legacy Raw log search:
##### Open from the Settings menu
To open the Parser extensions page from the Settings menu:
In the navigation bar, select SIEM Settings > Parsers.
The Parsers table displays a list of default parsers by log type.
Find the log type that you want to extend, click the more_vert Menu > Create Extension.
The Parser extensions page opens.
##### Open from a Raw log search
To open the Parser extensions page from a Raw log search:  Go to Investigation > SIEM Search. In the search field, add the prefix `raw =` to your search argument and enclose the search term in quotation marks. For example, `raw = "example.com"`. Click Run Search. The results are displayed in the Raw Logs panel. Click a log (row) in the Raw Logs panel. The Event View panel is displayed. Click the Raw Log tab in the Event View panel. The raw log is displayed.
Click the Manage Parser > Create Extension > Next.
The Parser extensions page opens.
##### Open from a legacy Raw log search
To open the Parser extensions page from a legacy Raw log search:  Use the legacy Raw log search to search for records similar to those that will be parsed. Select an event from the Events > Timeline panel. Expand the Event Data panel.
Click the Manage Parser > Create Extension > Next.
The Parser extensions page opens.
#### Parser extensions page
The page displays the Raw log and Extension definition panels:
Raw log panel:
This displays sample raw log data for the selected log type. If you opened the page from the Raw log search the sample data is the result of your search. You can format the sample using the View as menu (RAW, JSON, CSV, XML, etc.) and the Wrap Text checkbox.
Check that the sample of raw log data displayed is representative of the logs that the parser extension will process.
Click Preview UDM Output to see the UDM output for the sample raw log data.
Extension definition panel:
This lets you define a parser extension using one of two mapping instruction approaches: Map data fields (no-code) or Write code snippet. You can't use both approaches in the same parser extension.
Depending on the approach you choose, you can either specify the source log data fields to extract from the incoming raw logs and map them to the corresponding UDM fields, or you can write a code snippet to perform these tasks and more.
#### Select the extension approach
Note: The Extension method field in the Parser extensions page refers to the "approach" you use to define the parser extension.
In the Parser extensions page, Extension definition panel, in the Extension method field, select one of the following approaches to create the parser extension:
Map data fields (no-code) approach:
This approach lets you specify the fields in the raw log and map them to destination UDM fields.
This approach works with the following raw log formats:  Native JSON, native XML, or CSV. Syslog header plus native JSON, native XML, or CSV. You can create a data field type mapping instructions for raw logs in these formats: `JSON`, `XML`, `CSV`, `SYSLOG + JSON`, `SYSLOG + XML`, and `SYSLOG + CSV`.
See the next steps, Create no-code (Map data fields) instructions.
Write code snippet approach:
This approach lets you use Logstash-like syntax to specify instructions to extract and transform values from the raw log and assign them to UDM fields in the UDM record.
Code snippets use the same syntax and sections as default (or custom) parsers. For more information, see Parser syntax.
This approach works with all supported data formats for that log type.
See the next steps, Create code snippet instructions.
## Create no-code (Map data fields) instructions
The no-code approach (also called the Map data fields method) lets you specify the paths of the raw log fields and map them to corresponding destination UDM fields.
Before you create a parser extension using the no-code approach, you must have worked through these sections:  Create parser extensions Get started Select the extension approach, and select the Map data fields option.
The next steps to define the parser extension are:  Set the Repeated fields selector Define a data mapping instruction for each field Submit and activate the parser extension
### Set the Repeated fields selector
In the Extension definition panel, in the Repeated Fields field, set how the parser extension should save a value to repeated fields (fields that support an array of values, for example `principal.ip`):  Append Values: The newly extracted value is appended to the existing set of values stored in the UDM array field. Replace Values: The newly extracted value replaces the existing set of values in the UDM array field, previously stored by the default parser.
Settings in the Repeated Fields selector do not affect non-repeated fields.
For details, see More about the Repeated fields selector.
### Define a data mapping instruction for each field
Define a data mapping instruction for each field you want to extract from the raw log. The instruction should specify the path of the origin field in the raw log and map it to the destination UDM field.
If the raw log sample displayed in the Raw log panel contains a Syslog header, then the Syslog and Target fields are displayed. (Some log formats don't contain a Syslog header, for example, native JSON, native XML, or CSV.)
Google SecOps will need the Syslog and Target fields to pre-preprocess the Syslog header, to extract the structured portion of the log.
Define these fields:
Syslog: This is a user-defined pattern that preprocesses and separates a Syslog header from the structured portion of a raw log.
Specify the extraction pattern, using Grok and regular expressions, that identifies the Syslog header and the raw log message. For details, see Define the Syslog extractor fields.
Target: Variable name in the Syslog field that stores the structured portion of the log.
Specify the variable name in the extraction pattern that stores the structured portion of the log.
This is an example of an extraction pattern and a variable name for the Syslog and Target fields, respectively.
After entering values in the Syslog and Target fields, click the Validate button.
The validation process checks for both syntax and parsing errors, then returns either of the following:  Success: The data mapping fields appear. Define the remainder of the parser extension. Failure: An error message appears. Correct the error condition before continuing.
Optionally, define a precondition instruction.
A precondition instruction identifies a subset of the raw logs that the parser extension processes by matching a static value to a field in the raw log. If an incoming raw log meets the precondition criteria then the parser extension applies the mapping instruction. If the values don't match, the parser extension does not apply the mapping instruction.
Complete the following fields:  Precondition Field: Field identifier in the raw log containing the value to be compared. Enter either the full path to the field if the log data format is JSON or XML, or the column position if the data format is CSV. Precondition Operator: Select `EQUALS` or `NOT EQUALS`. Precondition Value: The static value that will be compared with the Precondition Field in the raw log.
For another example of a precondition instruction, see No-code - Extract fields with precondition value.
Map the raw log data field to the destination UDM field:
Raw Data Field: Enter either the full path to the field if the log data format is JSON (for example: `jsonPayload.connection.dest_ip`) or XML (for example: `/Event/Reason-Code`), or the column position if the data format is CSV (note: index positions start at 1).
Destination Field: Enter the fully qualified UDM field name where the value will be stored, for example `udm.metadata.collected_timestamp.seconds`.  Important: If the raw log is in JSON format, the data type of a log value must match the data type of its corresponding destination UDM field. For example, if the log records `packets sent` as a string (`"packets_sent":"16"`) and you attempt to map this to the `network.sent_bytes` UDM field, which has a `uint64` data type, the instruction will fail. This requirement does not apply to logs in CSV and XML format.
To continue adding more fields, click Add, and enter all the mapping instruction details for the next field.
For another example of mapping the fields, see No-code - Extract fields.
### Submit and activate the parser extension
Once you've defined data mapping instructions for all the fields you intend to extract from the raw log, submit and activate the parser extension.
Click Submit to save and validate the mapping instruction.
Google SecOps validates the mapping instructions:  If the validation process succeeds, the state changes to Live and the mapping instructions begin processing incoming log data.
If the validation process fails, the state changes to Failed and an error is displayed in the Raw Log field. Note: While a parser extension is being validated, you cannot edit the data mapping instructions.
This is an example of a validation error:
```
  ERROR: generic::unknown: pipeline.ParseLogEntry failed: LOG_PARSING_CBN_ERROR:
  "generic::invalid_argument: pipeline failed: filter mutate (7) failed: copy failure:
  copy source field \"jsonPayload.dest_instance.region\" must not be empty
  (try using replace to provide the value before calling copy)

  "LOG: {"insertId":"14suym9fw9f63r","jsonPayload":{"bytes_sent":"492",
  "connection":{"dest_ip":"10.12.12.33","dest_port":32768,"protocol":6,
  "src_ip":"10.142.0.238","src_port":22},"end_time":"2023-02-13T22:38:30.490546349Z",
  "packets_sent":"15","reporter":"SRC","src_instance":{"project_id":"example-labs",
  "region":"us-east1","vm_name":"example-us-east1","zone":"us-east1-b"},
  "src_vpc":{"project_id":"example-labs","subnetwork_name":"default",
  "vpc_name":"default"},"start_time":"2023-02-13T22:38:29.024032655Z"},
  "logName":"projects/example-labs/logs/compute.googleapis.com%2Fvpc_flows",
  "receiveTimestamp":"2023-02-13T22:38:37.443315735Z","resource":{"labels":
  {"location":"us-east1-b","project_id":"example-labs",
    "subnetwork_id":"00000000000000000000","subnetwork_name":"default"},
    "type":"gce_subnetwork"},"timestamp":"2023-02-13T22:38:37.443315735Z"}

```
Lifecycle states of a parser extension
Parser extensions have the following lifecycle states:
`DRAFT`: Newly created parser extension which has not yet been submitted.
`VALIDATING`: Google SecOps is validating the mapping instructions against existing raw logs to ensure that fields are parsed with no errors.
`LIVE`: The parser extension passed validation and is now in production. It extracts and transforms data from incoming raw logs into UDM records.
`FAILED`: The parser extension failed validation.
### More about the Repeated fields selector
Some UDM fields store an array of values, such as the principal.ip field. The Repeated fields selector lets you control how your parser extension will store newly extracted data in a repeated field:
Append values:
The parser extension will append the newly extracted value to the array of existing values in the UDM field.
Replace Values:
The parser extension will replace the array of existing values in the UDM field with the newly extracted value.
A parser extension can map data to a repeated field only when the repeated field is at the lowest level of the hierarchy. For example:  Mapping values to `udm.principal.ip` is supported because the repeated `ip` field is at the lowest level of the hierarchy, and `principal` is not a repeated field. Mapping values to `udm.intermediary.hostname` is not supported because `intermediary` is a repeated field, and is not at the lowest level of the hierarchy.
The following table provides examples of how the Repeated Fields selector configuration affects the generated UDM record.    Repeated Fields selection Example log Parser extension configuration Generated result     Append Values `{"protoPayload":{"@type":"type.AuditLog","authenticationInfo":{"principalEmail":"admin@cmmar.co"},"requestMetadata":{"callerIp":"1.1.1.1, 2.2.2.2"}}}` Precondition Field: `protoPayload.requestMetadata.callerIp` Precondition Value: `" "` Precondition Operator: `NOT_EQUALS` Raw Data Field: `protoPayload.requestMetadata.callerIp` Destination Field: `event.idm.read_only_udm.principal.ip`  `metadata:{event_timestamp:{}.....}principal:{Ip:"1.1.1.1, 2.2.2.2"} } }`   Append Values `{"protoPayload":{"@type":"type.AuditLog","authenticationInfo":{"principalEmail":"admin@cmmar.co"},"requestMetadata":{"callerIp":"2.2.2.2, 3.3.3.3", "name":"Akamai Ltd"}}}` Precondition 1: Precondition Field:`protoPayload.requestMetadata.callerIp` Precondition Value: `" "` Precondition Operator: `NOT_EQUALS` Raw Data Field: `protoPayload.requestMetadata.callerIp` Destination Field: `event.idm.read_only_udm.principal.ip`
Precondition 2: Raw Data Field: `protoPayload.requestMetadata.name` Destination Field: `event.idm.read_only_udm.metadata.product_name`  Events generated by prebuilt parser before applying extension.  `metadata:{event_timestamp:{} ... principal:{ip:"1.1.1.1"}}}`
Output after applying extension.  ` timestamp:{} idm:{read_only_udm:{metadata:{event_timestamp:{} .... product_name: "Akamai Ltd"}principal:{ip:"1.1.1.1, 2.2.2.2, 3.3.3.3"}}}`     Replace Values `{"protoPayload":{"@type":"type..AuditLog","authenticationInfo":{"principalEmail":"admin@cmmar.co"},"requestMetadata":{"callerIp":"2.2.2.2"}}}` Precondition Field: `protoPayload.authenticationInfo.principalEmail` Precondition Value: `" "` Precondition Operator: `NOT_EQUALS` Raw Data Field: `protoPayload.authenticationInfo.principalEmail` Destination Field: `event.idm.read_only_udm.principal.ip`  UDM events generated by prebuilt parser before applying extension. `timestamp:{} idm:{read_only_udm:{metadata:{event_timestamp:{} ... principal:{ip:"1.1.1.1"}}}`
UDM output after applying extension `timestamp:{} idm:{read_only_udm:{metadata:{event_timestamp:{} ....} principal:{ip:"2.2.2.2"}}}`
### More about the Syslog extractor fields
The Syslog extractor fields enable you to separate the Syslog header from a structured log by defining the Grok, regular expression, plus a named token in the regular expression pattern to store the output.
#### Define the Syslog extractor fields
Values in the Syslog and Target fields work together to define how the parser extension separates the Syslog header from the structured portion of a raw log. In the Syslog field, you define an expression using a combination of Grok and regular expression syntax. The expression includes a variable name that identifies the structured portion of the raw log. In the Target field, you specify that variable name.
The following example illustrates how these fields work together.
This is an example of a raw log:
` <13>1 2022-09-14T15:03:04+00:00 fieldname fieldname - - - {"timestamp": "2021-03-14T14:54:40.842152+0000","flow_id": 1885148860701096, "src_ip": "10.11.22.1","src_port": 51972,"dest_ip": "1.2.3.4","dest_port": 55291,"proto": "TCP"} `
The raw log contains the following sections:
Syslog header: `<13> 2022-09-14T15:03:04+00:00 fieldname fieldname - - - `
JSON formatted event: `{"timestamp": "2021-03-14T14:54:40.842152+0000","flow_id": 1885148860701096, "src_ip": "10.11.22.1","src_port": 51972,"dest_ip": "1.2.3.4","dest_port": 55291,"proto": "TCP"}`
To separate the Syslog header from the JSON portion of the raw log, use the following example expression in the Syslog field: ` %{TIMESTAMP_ISO8601} %{WORD} %{WORD} ([- ]+)?%{GREEDYDATA:msg} `  This portion of the expression identifies the Syslog header: `%{TIMESTAMP\_ISO8601} %{WORD} %{WORD} ([- ]+)?` This portion of the expression captures the JSON segment of the raw log: `%{GREEDYDATA:msg}`
This example includes the variable name `msg`. You choose the variable name. The parser extension extracts the JSON segment of the raw log and assigns it to the variable `msg`. Important: The value `message` is reserved and cannot be used as a variable name. An error will be returned when validating the expression.
In the Target field, enter the variable name `msg`. The value stored in the `msg` variable is input to the data field mapping instructions you create in the parser extension.
Using the example raw log, the following segment is input to data mapping instruction:
` {"timestamp": "2021-03-14T14:54:40.842152+0000","flow_id": 1885148860701096, "src_ip": "10.11.22.1","src_port": 51972,"dest_ip": "1.2.3.4","dest_port": 55291,"proto": "TCP"} `
The following shows the completed Syslog and Target fields:
The following table provides more examples with sample logs, the Syslog extraction pattern, Target variable name, and the result.    Sample raw log Syslog field Target field Result     `<13>1 2022-07-14T15:03:04+00:00 suricata suricata - - - {\"timestamp\": \"2021-03-14T14:54:40.842152+0000\",\"flow_id\": 1885148860701096,\"in_iface\": \"enp94s0\",\"event_type\": \"alert\",\"vlan\": 522,\"src_ip\": \"1.1.2.1\",\"src_port\": 51972,\"dest_ip\": \"1.2.3.4\",\"dest_port\": 55291,\"proto\": \"TCP\"}"` `%{TIMESTAMP_ISO8601} %{WORD} %{WORD} ([- ]+)?%{GREEDYDATA:msg}` msg `field_mappings { field: "msg" value: "{\"timestamp\": \"2021-03-14T14:54:40.842152+0000\",\"flow_id\": 1885148860701096,\"in_iface\": \"enp94s0\",\"event_type\": \"alert\",\"vlan\": 522,\"src_ip\": \"1.1.2.1\",\"src_port\": 51972,\"dest_ip\": \"1.2.3.4\",\"dest_port\": 55291,\"proto\": \"TCP\"}" }`    `<13>1 2022-07-14T15:03:04+00:00 suricata suricata - - - {\"timestamp\": \"2021-03-14T14:54:40.842152+0000\"} - - - {\"timestamp\": \"2021-03-14T14:54:40.842152+0000\",\"flow_id\": 1885148860701096,\"in_iface\": \"enp94s0\",\"event_type\": \"alert\",\"vlan\": 522,\"src_ip\": \"1.1.2.1\",\"src_port\": 51972,\"dest_ip\": \"1.2.3.4\",\"dest_port\": 55291,\"proto\": \"TCP\"}` `%{TIMESTAMP_ISO8601} %{WORD} %{WORD} ([- ]+)?%{GREEDYDATA:msg1} ([- ]+)?%{GREEDYDATA:msg2}` msg2 `field_mappings { field: "msg2" value: "{\"timestamp\": \"2021-03-14T14:54:40.842152+0000\",\"flow_id\": 1885148860701096,\"in_iface\": \"enp94s0\",\"event_type\": \"alert\",\"vlan\": 522,\"src_ip\": \"1.1.2.1\",\"src_port\": 51972,\"dest_ip\": \"1.2.3.4\",\"dest_port\": 55291,\"proto\": \"TCP\"}" }`   `"<13>1 2022-07-14T15:03:04+00:00 suricata suricata - - - {\"timestamp\": \"2021-03-14T14:54:40.842152+0000\"} - - - {\"timestamp\": \"2021-03-14T14:54:40.842152+0000\",\"flow_id\": 1885148860701096,\"in_iface\": \"enp94s0\",\"event_type\": \"alert\",\"vlan\": 522,\"src_ip\": \"1.1.2.1\",\"src_port\": 51972,\"dest_ip\": \"1.2.3.4\",\"dest_port\": 55291,\"proto\": \"TCP\"}"` `%{TIMESTAMP_ISO8601} %{WORD} %{WORD} ([- ]+)?%{GREEDYDATA:message} ([- ]+)?%{GREEDYDATA:msg2}` msg2 `Error - message already exists in state and not overwritable.`
### More about assigning UDM `metadata.event_type` fields
When assigning a UDM `metadata.event_type` field to a UDM record, it is validated to ensure the required related fields are present in the UDM record. Each UDM `metadata.event_type` requires a different set of related fields, for example, a `USER_LOGIN` event without a `user` is not useful.
If a required related field is missing, the UDM validation returns an error:
```
  "error": {
    "code": 400,
    "message": "Request contains an invalid argument.",
    "status": "INVALID_ARGUMENT"
  }

```
A grok parser returns a more detailed error:
```
  generic::unknown:
  invalid event 0: LOG_PARSING_GENERATED_INVALID_EVENT:
  "generic::invalid_argument: udm validation failed: target field is not set"

```
To find required fields for a UDM `event_type` to assign, use the following resources, where the adoption guides supplement the UDM Usage Guide by providing the minimum mandatory UDM fields needed to populate a given UDM `metadata.event_type`.
Google SecOps documentation: UDM Usage Guide - Required and optional UDM fields for each event type
Adoption Guide: Deep Dive into UDM Parsing - Part 1.1
Adoption Guide: Basics of GoStaash-Parsing
For example, open the document and search for the `GROUP_CREATION` event type.
You should see the following minimum UDM fields, presented as a UDM Object:
```
  {
      "metadata": {
          "event_timestamp": "2023-07-03T13:01:10.957803Z",
          "event_type": "GROUP_CREATION"
      },
      "principal": {
          "user": {
              "userid": "pinguino"
          }
      },
      "target": {
          "group": {
              "group_display_name": "foobar_users"
          }
      }
  }

```
## Create code snippet instructions
The code snippet approach lets you use Logstash-like syntax to define how to extract and transform values from the raw log, and assign them to UDM fields in the UDM record.
Before you create a parser extension using the code snippet approach, you must have worked through these sections:  Create parser extensions Get started Select the extension approach, and select the Write code snippet option.
The next steps to define the parser extension are:  For tips and best practices, see Tips and best practices when writing code snippet instructions. Create a code snippet instruction Submit a code snippet instruction
### Tips and best practices when writing code snippet instructions
Code snippet instructions can fail due to issues like incorrect Grok patterns, failed rename or replace operations, or syntax errors. See the following for tips and best practices:  Common practices in parser code Parse unstructured text using a Grok function
### Create a code snippet instruction
Code snippet instructions use the same syntax and sections as the default (or custom) parser:  Section 1. Extract data from the raw log. Section 2. Transform the extracted data. Section 3. Assign one or more values to a UDM field. Section 4. Bind UDM event fields to the `@output` key.
To create a parser extension using the code snippet approach, do the following:  In the Parser extensions page, CBN Snippet panel, enter a code snippet to create the parser extension. Click Validate to validate the mapping instructions.
#### Code snippet instruction examples
Note: For the full list of examples, covering many log types and scenarios, see code snippet parser extension creation examples.
The following example illustrates a code snippet.
This is an example the raw log:
```
  {
      "insertId": "00000000",
      "jsonPayload": {
          ...section omitted for brevity...
          "packets_sent": "4",
          ...section omitted for brevity...
      },
      "timestamp": "2022-05-03T01:45:00.150614953Z"
  }

```
This is an example of a code snippet that maps the value in `jsonPayload.packets_sent` to the `network.sent_bytes` UDM field:
```
filter {
  mutate {
    replace => {
      "jsonPayload.packets_sent" => ""
    }
  }
  # Section 1. extract data from the raw JSON log
  json {
    source => "message"
    array_function => "split_columns"
    on_error => "_not_json"
  }
  if [_not_json] {
    drop {
      tag => "TAG_UNSUPPORTED"
    }
  } else {
    # Section 2. transform the extracted data
    if [jsonPayload][packets_sent] not in ["", 0] {
      mutate {
        convert => {
          "jsonPayload.packets_sent" => "uinteger"
        }
        on_error => "_exception1"
      }
      # Section 3. assign the value to a UDM field
      mutate {
        Replace => {
          "event.idm.read_only_udm.network.sent_bytes" => "jsonPayload.packets_sent"
        }
        on_error => "_exception2"
      }
      if ![_exception1] and![_exception2] {
        # Section 4. Bind the UDM fields to the @output key
        mutate {
          merge => {
            "@output" => "event"
          }
        }
      }
    }
  }
}

```
Note: If you define two separate events in the code snippet, and create two output statements, the parser extension saves the fields from both events into a single UDM record.
### Submit a code snippet instruction
Click Submit to save the mapping instructions.
Google SecOps validates the mapping instructions.  If the validation process succeeds, the state changes to Live and the mapping instructions begin processing incoming log data. If the validation process fails, the state changes to Failed and an error is displayed in the Raw Log field.  Note: While a parser extension is being validated, you cannot edit the data mapping instructions.
## Manage existing parser extensions
You can view, edit, delete, and control access to existing parser extensions.
### View an existing parser extension
In the navigation bar, select SIEM Settings > Parsers. In the Parsers list, find the parser (log type) that you want to view. Parsers with a parser extension are indicated by the `EXTENSION` text next to their name.
Go to that row, then click the more_vert Menu > View Extension.
The View Custom/Prebuilt Parser > Extension tab appears showing details about the parser extension. The summary panel displays the `LIVE` parser extension by default.
### Edit a parser extension
Open the View Custom/Prebuilt Parser > Extension tab, as described in View an existing parser extension.
Click the Edit Extension button.
The Parser extensions page appears.
Edit the parser extension.
To cancel editing and discard changes, click Discard Draft.
To delete the parser extension at any time, click Delete Failed Extension.
When you are finished editing the parser extension, click Submit.
The validation process runs to validate the new configuration. Note: While a parser extension is being validated, you cannot edit the data mapping instructions.
### Delete a parser extension
Open the View Custom/Prebuilt Parser > Extension tab, as described in View an existing parser extension.
Click the Delete Extension button.
### Control access to parser extensions
By default, users with the Administrator role can access parser extensions. You can control who can view and manage parser extensions. For more information about managing Users and Groups, or assigning roles, see Role Based Access Control for more information.
The new roles in Google SecOps are summarized in the following table.    Feature Action Description     Parser Delete Delete parser extensions.   Parser Edit Create and edit parser extensions.   Parser View View parser extensions.
### Remove UDM field mappings using parser extensions
You can use parser extensions to remove an existing UDM field mapping.  Click SIEM Settings > Parsers. Use either of the following methods to view the Parser extension page:  For an existing extension, click more_vert Menu > Extend Parser > View Extension. For new parser extensions, click more_vert Menu > Extend Parser > Create Extension.
Select Write code snippet as the extension method to add a custom code snippet that removes values for specific UDM fields.
For an existing extension, on the Parser extension pane, click Edit and then add the code snippet.
See Code snippet - Remove existing mappings for example snippets.
Follow the steps in the Submit a code snippet instruction to submit the extension.