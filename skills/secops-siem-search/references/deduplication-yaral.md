# Source: https://docs.cloud.google.com/chronicle/docs/investigation/deduplication-yaral

# Use deduplication in Search and Dashboards
Supported in:    Google secops   SIEM
In Google Security Operations, search results can include duplicates when multiple systems log the same event (for example, an authentication system and a firewall both logging a single login).
To return only unique results, use the `dedup` section in your YARA-L syntax. Adding UDM fields to this section makes sure that the query returns a single result for each distinct combination of values.
## Performance guidelines
The `dedup` operator processes all data within a time range as a single unit to maintain correctness.  Optimal ranges: Performance is best for ranges <= 1 day. Latency: Ranges between 7–30 days significantly increase latency and can cause query timeouts.
We recommend to always use the shortest possible time range suitable for your investigation when you apply the `dedup` operator.
## Deduplication by query type
Deduplication behavior depends on whether your query uses aggregations and applies to the following types of search and dashboard queries.
### Aggregated search queries
Aggregated search queries include `match`, `match` and `outcome`, or `aggregated outcome` sections. Deduplication occurs after outcomes are determined.
For these queries, add the following fields to the `dedup` section:  Fields from the `match` section *Fields from the `outcome` section
### UDM search queries
UDM search queries exclude the `match`, `outcome`, or aggregated `outcome` sections. Note: UDM search queries can include an `outcome` section as long as there aren't any aggregates and there isn't a `match` section.
To deduplicate UDM searches, add these fields to the `dedup` section:  Any non-repeated, non-array, and non-grouped event fields. Placeholder fields from the `events` section. Outcome variables from the `outcome` section (if there are no aggregates).
## Deduplication examples in Search
This section shows the YARA-L syntax and can be run in Search.
### Example: Search for unique IP addresses
The following example query identifies network connections between internal and external IPs, deduplicated by the internal IP (`principal.ip`):
```
events:
   metadata.event_type = "NETWORK_CONNECTION"
   target.ip != ""
   principal.ip != ""

match:
   target.ip, principal.ip

dedup:
   principal.ip

```
### Example: Unique IP addresses with traffic volume
Similar to the previous example, the following example search displays network connection events with unique IP addresses. Applying `dedup` to `principal.ip` narrows results to events associated with unique IPs. The `outcome` section displays the total bytes sent between `principal.ip` and `target.ip`, ordering results from highest to lowest traffic volume.
```
events:
   metadata.event_type = "NETWORK_CONNECTION"
   target.ip != ""
   principal.ip != ""

match:
   target.ip, principal.ip

outcome:
   $total_bytes = sum(network.sent_bytes)

dedup:
   principal.ip

order:
   $total_bytes desc

```
### Example: Basic UDM deduplication
The following example searches for a high-level view of unique hostnames accessed across all log types. Applying `dedup` to `target.hostname` narrows results to events associated with unique external hostnames. Note: This format is effective for queries that don't require aggregations.
```
metadata.log_type != ""

dedup:
    target.hostname

```
The following is an equivalent example without the `dedup` option. It typically returns substantially more events.
```
metadata.log_type != "" AND target.hostname != ""

```
### Example: Unique hostnames
Similar to the previous example, this search displays network connection events with unique hostnames. Applying the `dedup` option to `principal.hostname` narrows results to events associated with unique hosts:
```
events:
   metadata.event_type = "NETWORK_CONNECTION"
   target.hostname != ""
   principal.hostname != ""

match:
   target.hostname, principal.hostname

outcome:
   $total_bytes = sum(network.sent_bytes)

dedup:
   principal.hostname

order:
   $total_bytes desc

```