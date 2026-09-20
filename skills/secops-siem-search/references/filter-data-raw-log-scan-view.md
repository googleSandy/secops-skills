# Source: https://docs.cloud.google.com/chronicle/docs/investigation/filter-data-raw-log-scan-view

# Filter data in raw log search
Supported in:    Google secops   SIEM
This document explains the available methods for filtering raw logs using the Search bar, which you can access on the landing page or the dedicated Search page.
Choose one of the following methods:
## Use the `raw=` format
When using the `raw=` format, use these parameters to filter raw logs:
`parsed`: Filters logs based on their parsing status.  `parsed=true`: Returns only parsed logs. `parsed=false`: Returns only unparsed logs.
`log_source=IN["log_source_name1", "log_source_name2"]`: Filters by log type.
### How to find unparsed raw logs
Unparsed logs don't generate UDM records. You can't query them using UDM fields (such as `metadata.log_type = "UNPARSED"`). To search for unparsed logs:  In the Google SecOps console, go to Investigation > SIEM Search. In the search box menu, change the search mode from UDM Search to Raw Log Search. Select your target time range (for example, Past 1 hour or Past 24 hours).
Query for unparsed logs using the `parsed = false` filter:
```
raw = /.+/ parsed = false

```
To target specific feed log types, combine `parsed = false` with `log_source`:
```
raw = /.+/ parsed = false log_source IN ["CUSTOM_JSON", "OKTA"]

```
## Use the Raw log search prompt (legacy method)
To use the Raw Log Search prompt to filter raw logs, do the following:
On the search bar, enter your search string or regular expressions, and then click Search.
In the menu, select Raw Log Search to display the search options.
Specify the Start Time and End Time (the default is 1 week) and click Search.
The Raw Log Search view displays raw data events. You can filter results by `DNS`, `Webproxy`, `EDR`, and `Alert`. Note: These filters don't apply to event types, such as `GENERIC`, `EMAIL`, and `USER`.
You can use regular expressions to search for and match sets of character strings within your security data using Google SecOps. Regular expressions let you narrow your search down using fragments of information, as opposed to using a complete domain name, for example.
The following Procedural Filtering options are available in the Raw Log Search view:
Product Event Type
There are known inconsistencies between how events are displayed across views in the SecOps Console legacy Raw Log Search page: ● Raw Log view: Displays the Event type based on the raw `event_log_type` value. For example `FILE_COPY`. ● UDM event fields view: Displays the `metadata.event_type` field based on the `event_log_type` value. For example `FILE_COPY`. ● Procedural Filtering view: Displays the Event type field based on the `network.application_protocol` value. For example `DNS`.  Log Source
Network Connection Status
TLD