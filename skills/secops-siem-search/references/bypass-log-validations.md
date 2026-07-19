# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/bypass-log-validations

# Bypass Log Validation for parser extensions and custom parsers
Supported in:    Google secops   SIEM
The custom parser and parser extension validation process typically enforces a rigorous check against sample logs from the preceding 30 days to ensure functional integrity. However, there are scenarios where customers may need to deploy an extension despite validation failures, such as when no logs have been ingested in the last 30 days or when current logs don't yet reflect a new format. Note: In addition to the API-based workflow to bypass mandatory log validation for parser extensions or custom parsers, you can skip log validation using the Google SecOps platform. To skip log validation using the Google SecOps platform, in the relevant Parser Extension or Custom Parser page, click Skip Log Validation > Confirm > Submit > Submit.
This document outlines the API-based workflow to bypass mandatory log validation for parser extensions and custom parsers.
Component  Definition    API Method  `CreateParserExtension` (for Extensions) or `CreateParser` (for Custom Parsers)    Bypass Flag  `validation_skipped`    Flag Type  Boolean (Default: false)    Scope  ParserExtension proto (for extensions) and Parser proto (for custom parsers )
When you skip validation, the parser shows as `validation_skipped` status. Because this is an asynchronous operation, initial calls to the Create API will show a new state. However, subsequent Get API requests will reflect the `validation_skipped` status once processed.
## API execution
Execute the relevant Create API call with the `validation_skipped` flag enabled. You can use this flag and make the custom parser or extension active, even when no logs have been ingested at all for the customer and logtype.
## API examples for parser extensions
`CreateParserExtension` Request
```
parent:    "projects/dummy/locations/us/instances/dummy/logTypes/dummy"
parser_extension {
  cbn_snippet: "# Author:dummy@google.com\n# Note: Pls don\'t delete or update.\n\nfilter {\n  mutate {\n    convert => {\n      \"message\" => \"integer\"\n    }\n  }\n   mutate {\n    merge => {\n      \"@output\" => \"event\"\n    }\n  }\n}"
  validation_skipped: true
}

```
`CreateParserExtension` Response
```
google.cloud.chronicle.v1main.ParserExtension { # [619B]
name: "projects/dummy/locations/us/instances/dummy/logTypes/dummy/parserExtensions/dummy"
state: NEW
create_time: { # [12B]
seconds: 1775133417
nanos: 697098000
}
cbn_snippet: "# Author:dummy@google.com\n# Note: Pls don\'t delete or update.\n\nfilter {\n  mutate {\n    convert => {\n      \"message\" => \"integer\"\n    }\n  }\n   mutate {\n    merge => {\n      \"@output\" => \"event\"\n    }\n  }\n}"
extension_validation_report:
"projects/dummy/locations/us/instances/dummy/logTypes/dummy/parserExtensions/dummy/extensionValidationReports/dummy"
validation_skipped: true
}

```
`GetParserExtension` Request
```
name: "projects/dummy/locations/us/instances/dummy/logTypes/dummy/parserExtensions/dummy"

```
`GetParserExtension` Response
```
google.cloud.chronicle.v1main.ParserExtension { # [862B]
name: "projects/dummy/locations/us/instances/dummy/logTypes/dummy/parserExtensions/dummy"
state: VALIDATION_SKIPPED
create_time: { # [12B]
seconds: 1775133417
nanos: 697098000
}
cbn_snippet: "# Author:dummy@google.com\n# Note: Pls don\'t delete or update.\n\nfilter {\n  mutate {\n    convert => {\n      \"message\" => \"integer\"\n    }\n  }\n   mutate {\n    merge => {\n      \"@output\" => \"event\"\n    }\n  }\n}"
extension_validation_report: 
"projects/dummy/locations/us/instances/dummy/logTypes/dummy/parserExtensions/dummy/extensionValidationReports/dummy"
validation_report:"projects/dummy/locations/us/instances/dummy/logTypes/dummy/parserExtensions/dummy/validationReports/dummy"
state_last_changed_time: { # [12B]
seconds: 1775133417
nanos: 976250000
}
last_live_time: { # [11B]
seconds: 1775133418
nanos: 189172000
}
validation_skipped: true
}

```
Once you have created the parser extensions, you can deploy them using the `ActivateParserExtension` method.
## API examples for custom parsers
`CreateParser` Request
```
parent: "projects/dummy/locations/us/instances/dummy/logTypes/dummy"
parser: { # [260B]
cbn: "# Author: dummy@google.com\n# Note: Pls don\'t delete or update. This is used by normalizer custom prober.\n\nfilter {\n  mutate {\n    convert => {\n      \"message\" => \"integer\"\n    }\n  }\n   mutate {\n    merge => {\n      \"@output\" => \"event\"\n    }\n  }\n}"
validation_skipped: true
}

```
`CreateParser` Response
```
google.cloud.chronicle.v1main.Parser { # [489B]
name: "projects/dummy/locations/us/instances/dummy/logTypes/dummy/parsers/dummy"
creator: { # [85B]
customer:"projects/dummy/locations/us/instances/dummy"
source: CUSTOMER
}
cbn: "# Author: dummy@google.com\n# Note: Pls don\'t delete or update. This is used by normalizer custom prober.\n\nfilter {\n  mutate {\n    convert => {\n      \"message\" => \"integer\"\n    }\n  }\n   mutate {\n    merge => {\n      \"@output\" => \"event\"\n    }\n  }\n}"
changelogs: { # [0B]
}
validation_stage: NEW
type: CUSTOM
state: INACTIVE
validation_skipped: true
}

```
`GetParser` Request
```
name: "projects/dummy/locations/us/instances/dummy/logTypes/dummy/parsers/dummy"

```
`GetParser` Response
```
name: "projects/dummy/locations/us/instances/dummy/logTypes/dummy/parsers/dummy"
creator: { # [85B]
customer:"projects/dummy/locations/us/instances/dummy"
source: CUSTOMER
}
cbn: "# Author:dummy@google.com\n# Note: Pls don\'t delete or update. This is used by normalizer custom prober.\n\nfilter {\n  mutate {\n    convert => {\n      \"message\" => \"integer\"\n    }\n  }\n   mutate {\n    merge => {\n      \"@output\" => \"event\"\n    }\n  }\n}"
create_time: { # [12B]
seconds: 1775135466
nanos: 795092000
}
changelogs: { # [0B]
}
validation_stage: VALIDATION_SKIPPED
type: CUSTOM
state: INACTIVE
validation_report:"projects/dummy/locations/us/instances/dummy/logTypes/dummy/parsers/dummy/validationReports/dummy"

```
Once you have created the custom parsers, you can deploy them using the `ActivateParser` method.
## Rejection criteria and risk
While the `validation_skipped` flag allows users to bypass checks against sample logs, it doesn't allow for the deployment of broken code. An extension or custom parser is still rejected if the extension or parser code contains syntax-related failures. The skip option is only viable if the extension is syntactically correct but failing due to parsing logic or lack of logs.
If a `validation_skipped` flag causes system issues or performance regressions, it may be deactivated by the Google internal engineering teams.