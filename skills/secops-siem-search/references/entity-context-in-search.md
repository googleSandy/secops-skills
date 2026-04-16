# Source: https://docs.cloud.google.com/chronicle/docs/investigation/entity-context-in-search

# Conduct a search for entity context data
Supported in:    Google secops   SIEM     Note: This feature is covered by Pre-GA Offerings Terms of the Google Security Operations Service Specific Terms. Pre-GA features might have limited support, and changes to pre-GA features might not be compatible with other pre-GA versions. For more information, see the Google SecOps Technical Support Service guidelines and the Google SecOps Service Specific Terms.
The Entity Context in Search feature enhances security investigations and incident response by letting users search for and view context events related to entities within their Google Security Operations account. Unlike searches limited to the standard Unified Data Model (UDM) event schema, this feature addresses the need to search beyond UDM event data, including UDM entity context, and providing deeper insights into security incidents.
## Key benefits
Security analysts and threat hunters can query contextual information about entities. Help root cause analysis, threat hunting, and forensics. Users can run statistical searches on entity context to understand telemetry patterns and impacted entities through telemetry analysis.
## Use Entity Context in Search
You can use entity context to gain insights from your search results in the following ways:  Search using UDM entity field names: Build your search queries using UDM entity field names. For example, to find all context events associated with a specific hostname, create a search using `graph.entity.hostname`. Access the Overview tab: The Overview tab provides a high-level summary of entities found in your search, leveraging information from the query that a user enters to display information. The Overview page displays information for entity types, such as `DOMAIN_NAME`, `IP_ADDRESS`, `ASSET`, `USER`, `FILE`, `GROUP`, and `RESOURCE`. Use the Entity tab: The Entity tab lists all entity context events received, including subcomponents like Trend Over Time, Snapshot Filter, Aggregations, and Events. The entities are categorized into timed and timeless entities, displayed in separate tabs. View aggregates: Aggregates are displayed for fields, similar to the UDM event search. The aggregations are further categorized into context types: Entity Context, Derived Context, and Global Context.  Note: The search feature has an autocomplete function. To receive suggestions in the drop-down, type specific elements such as `graph.entity` or `graph.metadata`. Typing generic terms like `graph` doesn't show relevant autocomplete options.
## Use case: Investigate a compromised user account
Consider the following scenario: a security analyst needs to investigate a potentially compromised user account (email@company.com). Follow these steps to investigate:
Identify the compromised user: An alert flags user email@company.com has been identified as a suspicious account.
Gather Entity Context information: Get contextual data about the user to understand the scope and impact.
Run queries: Use Entity Context in Search to run the following queries:  `graph.entity.user.email_addresses = "email@company.com"` to retrieve information about the user. `graph.entity.user.email_addresses = "email@company.com" AND graph.metadata.product_name = "Google Cloud Compute Context"` to check the product name and other metadata.
Analyze the Overview Tab: The Overview tab displays the entity summary for the user, including:  Check `First Seen Hour` and `Last Seen Hour` timestamps.   Note: `First Seen Hour` and `Last Seen Hour` timestamps are only available for IoCs and artifacts.  Review Hostnames, IP addresses, and MAC addresses (if available). Inspect hardware model, OS platform, and platform version.
Examine the Events Tab: View associated events for this user, including login attempts and anomalies.
Review Aggregates: Identify patterns and anomalies in entity context data, distributed into Entity Context, Derived Context, and Global Context.
## Examples of Search
To search for entity context data, use UDM entity field names in your search queries:  `graph.entity.hostname` `graph.entity.ip = "8.8.8.8" and graph.metadata.entity_type = "ASSET"`
The search results display key information about the entities, including:  Entity metadata Metrics (`First Seen Hour`, `Last Seen Hour`) Relations (`Entity`, `Direction`, `Entity_label`, `Entity_type`, `Relationship`) Depending on the entity type, specific fields, such as `Principal_ip` for assets, `Mail_id` for users, `File_name` for hashes/files, and `Domain_name` and `IP_address` for domains.
## Entity Context in search examples
This section provides practical examples for building on the UDM Entity Context feature to analyze entity statistics.
### UDM Entity stats search
To view available context sources and types, run the following UDM Entity stats search in UDM Search:
```
graph.metadata.source_type = $sourceType
graph.metadata.entity_type = $entityType
match:
  $sourceType, $entityType
outcome:
  $total = count(graph.metadata.product_entity_id)
order:
  $sourceType, $total desc
limit:
  100

```
The Time Picker shows active data within the Entity Graph, not when the context data was ingested.
Because UDM Entity Search uses the standard UDM Search interface, you can use features, such as the Aggregations panel (to view top or bottom values), the results table, and UDM Stats expanded results.
#### Example: View distinct `ENTITY_TYPE`
To expand on the UDM Entity Search, you can include the log source, namespace, and an outcome array to show distinct `ENTITY_TYPE`s observed, as follows:
```
graph.metadata.source_type = "ENTITY_CONTEXT"
$logType = strings.to_upper(graph.metadata.event_metadata.base_labels.log_types)
$namespace = strings.to_upper(graph.metadata.event_metadata.base_labels.namespaces)
match:
  $logType, $namespace
outcome:
  $total = count(graph.metadata.product_entity_id)
  $entityTypes = array_distinct(graph.metadata.entity_type)
order:
  $logType, $total desc
limit:
  100

```
#### Example: Refine your entities set
You can refine a specific set of entities using the UDM Search pivot feature. This refinement then generates a YARA-L query like the following:
```
graph.metadata.source_type = "ENTITY_CONTEXT"
$logType = strings.to_upper( graph.metadata.event_metadata.base_labels.log_types )
$namespace = strings.to_upper( graph.metadata.event_metadata.base_labels.namespaces )
AND strings.to_upper( graph.metadata.event_metadata.base_labels.log_types ) = "WINDOWS_AD"
AND strings.to_upper( graph.metadata.event_metadata.base_labels.namespaces ) = "ACME"

```
### Derived context
Google SecOps provides the following types of derived context:  `first_seen` and `last_seen` timestamps for each `ENTITY_TYPE` `Prevalence`: The number of assets that have accessed a given `ENTITY_TYPE`
#### `First Seen Hour` and `Last Seen Hour` timestamps
Google SecOps performs statistical analysis on incoming data and enriches entity context records with `first_seen` and `last_seen` timestamps:  The `first_seen_time` field captures the hour when an entity was first seen in the customer environment. The `last_seen_time` field records the hour of the most recent observation of that entity.
Users with a first seen hour in the last 7 days:
```
graph.metadata.entity_type = "USER"
graph.entity.user.userid != ""
graph.entity.user.first_seen_time.hours >= timestamp.current_hours()-(86400 * 7)

```
Domains first seen within the last 7 days:
```
graph.metadata.source_type = "DERIVED_CONTEXT"
graph.metadata.entity_type = "DOMAIN_NAME"
//optional, filter to only return FQDN
graph.entity.domain.name = /^([a-zA-Z0–9]([a-zA-Z0–9-]{0,61}[a-zA-Z0–9])?\.)+[a-zA-Z]{2,}$/
graph.entity.domain.first_seen_time.hours >= timestamp.current_hours()-(86400 * 7)

```
File (hashes) observed within the last 7 days:
```
graph.metadata.source_type = "DERIVED_CONTEXT"
graph.metadata.entity_type = "FILE"
//graph.entity.file.md5 != ""
//graph.entity.file.sha1 != ""
graph.entity.file.sha256 != ""
graph.entity.file.first_seen_time.hours >= timestamp.current_hours() - (86400 * 7)

```
The `ENTITY_TYPE` represents a `FILE` hash, for example, `entity.file.hash`. Within the `hash` object, the type can be one of the following:  `md5` `sha1` `sha256`
To search for a specific hash, you can run a UDM Entity Search for the given hash type:
```
// This will search ENTITY, DERIVED, and GLOBAL Source Types
graph.metadata.entity_type = "FILE"
graph.entity.file.sha256 = "eb5db1feadda5351c3b8fc0770e9f4c173484df5dc4a785bd1bdce7806a9e498"

```
### IP addresses
Derived `ENTITY_TYPES` of `IP_ADDRESS` can represent internal or external entities.
The following UDM Entity Stats search identifies recently observed `IP_ADDRESSES` and uses aggregate functions (in the outcome section) to count them by CIDR block:
```
graph.metadata.source_type = "DERIVED_CONTEXT"
graph.metadata.entity_type = "IP_ADDRESS"
//note, for IP addresses the first seen is under artifact, not ip
graph.entity.artifact.first_seen_time.hours >= timestamp.current_hours()-(86400 * 7)
outcome:
  $total = count(graph.metadata.product_entity_id)
  $classA = sum(if(net.ip_in_range_cidr(graph.entity.ip, "10.0.0.0/8"),1,0))
  $classB = sum(if(net.ip_in_range_cidr(graph.entity.ip, "172.16.0.0/12"),1,0))
  $classC = sum(if(net.ip_in_range_cidr(graph.entity.ip, "192.168.0.0/16"),1,0))
  $classD = sum(if(net.ip_in_range_cidr(graph.entity.ip, "224.0.0.0/4"),1,0))
  // we shouldn't see results here…
  $classE = sum(if(net.ip_in_range_cidr(graph.entity.ip, "240.0.0.0/4"),1,0))
  $thisNetwork = sum(if(net.ip_in_range_cidr(graph.entity.ip, "0.0.0.0/8"),1,0))
  $loopback = sum(if(net.ip_in_range_cidr(graph.entity.ip, "127.0.0.0/8"),1,0))
  $linklocal = sum(if(net.ip_in_range_cidr(graph.entity.ip, "169.254.0.0/16"),1,0))
  $benchmark = sum(if(net.ip_in_range_cidr(graph.entity.ip, "198.18.0.0/15"),1,0))
  $cgnat = sum(if(net.ip_in_range_cidr(graph.entity.ip, "10.64.0.0/10"),1,0))

```
To further investigate an unusual or unexpected range, you can run a UDM Entity search:
```
graph.metadata.source_type = "DERIVED_CONTEXT"
graph.metadata.entity_type = "IP_ADDRESS"
net.ip_in_range_cidr(graph.entity.ip, "198.18.0.0/15")

```
### Prevalence
Prevalence is always of the `DERIVED_CONTEXT` type. Caution: Including the `prevalence` argument can significantly increase the data queried, potentially leading to a Rule Error. If you encounter a Rule Error, refine your rule parameters. For example, add more filters or reduce the time range specified in the `match` section.
The following UDM Entity Search identifies domain names that are rarely observed. These domains are specifically associated with at most one distinct asset per day, during the query's time window (`day_max = 1`), and at most one distinct asset across the previous 10 days (`rolling_max = 1`).
This pattern is useful for detecting domains with limited interaction across your environment:
```
graph.metadata.source_type = "DERIVED_CONTEXT"
graph.metadata.entity_type = "DOMAIN_NAME"
//optional, filter to only return specific TLDs where the FQDN is more than X characters
//graph.entity.domain.name = /^.{40,}\.(?:sx|cc|st|ac|lc|wd|vg|tv|cm|gd)$/
graph.entity.domain.prevalence.rolling_max = 1
graph.entity.domain.prevalence.day_max = 1

```
Alternatively, you can turn this into an aggregate UDM Entity Stats search and aggregate the results:
```
graph.metadata.source_type = "DERIVED_CONTEXT"
graph.metadata.entity_type = "DOMAIN_NAME"
//optional, filter to only return FQDN
graph.entity.domain.name = /^.{40,}\.(?:sx|cc|st|ac|lc|wd|vg|tv|cm|gd)$/
$domain = graph.entity.domain.name
$length = strings.length(graph.entity.domain.name)
$tld = strings.extract_domain(graph.entity.domain.name)
graph.entity.domain.prevalence.day_max = 1
graph.entity.domain.prevalence.rolling_max = 1
match:
  $domain, $tld, $length
limit:
  10

```
## Basic UDM entity field searches
Here are additional examples of using the Entity Context in Search feature in Google SecOps, based on available sources:  `graph.entity.hostname` `graph.entity.ip = "8.8.8.8" and graph.metadata.entity_type = "ASSET"` `principal.ip` `principal.hostname="baz"` `principal.ip="1.2.3.4"` `network.dns.questions.name="youtube.com"`
### Pivoting from entity fields
Use entity fields to pivot and explore related data. Examples of pivot fields include:  `network.email.to` `network.email.cc` `principal.process.file.fileMetadata.pe.importHash` `principal.process.file.sha256` `network.dns.questions.name`
### Understand dynamic fields
The sources reference dynamic structured fields with prefixes, such as `additional`. You can search these fields within UDM events.
## Access control considerations
The system imposes a limit of 50 events on global context data. Both Global and Scoped users can see the data. Note: Global context data (WHOIS, Mandiant Fusion IoC, GCTI) may have restricted responses to prevent misuse. Similarly, derived context (prevalence) and entity context (AD, Workday) can also be subject to access limitations.
The following sources provide global context data:    Global context data Where a user can see or interact with this data Who can see it     Safe Browsing - Search- Rules All users   VirusTotal Relationships - Search- Rules All users   WHOIS - Search- Rules All users   Uppercase - Search- Rules All users   Open Source Intel IOC (`OPEN_SOURCE_INTEL_IOC`) - Search- Rules All users   Mandiant Active Breach IoC (`MANDIANT_ACTIVE_BREACH_IOC`) - IoC matches All users. Results are filtered for IoCs, associated to events that fall in User's data access scopes.   Mandiant Fusion IoC (`MANDIANT_FUSION_IOC`) - Search- Rules- Emerging Threats All users
## Limitations
Volume limits: 1M limit on cumulative results for both timed and timeless data. Global context data: There's a limit of 50 rows for sensitive global context data, such as `UPPERCASE_VT_PROTECTED`, `MANDIANT_ACTIVE_BREACH_IOC`, `MANDIANT_FUSION_IOC`, and `VIRUS_TOTAL_CONNECTIONS`. Data consistency: Last seen data can lag up to 2 hours. Related entities can show only a subset of the entities listed in an event.
Unsupported features:  Reverse lookups on entity fields, grouped field searches, Low Prevalence, and HeatMap. You can't Join between Entity context and Event queries.