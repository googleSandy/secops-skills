# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/entity-graph

# Using the Entity Context Graph (ECG)
Supported in:    Google secops   SIEM
This document is a comprehensive overview of the Entity Context Graph (ECG), its data sources, processing pipeline, and applications in rules and search. The ECG is a core entity data model providing essential context for advanced threat detection, investigation, and threat hunting in detection rules, search, and dashboards. The ECG processing pipeline (merges) contextual information across each Google SecOps environment.
Additionally, the ECG calculates summary metrics for entities such as prevalence (how often a specific entity occurs in your UDM data compared to other entities), an entity's `first-seen-time` and `last-seen-time`, as well as key enrichment sources and indicators of compromise (IOC) sources like Google Threat Intelligence (GTI), Safe Browsing, WHOIS, and VirusTotal data.
The ECG uses UDM events to do the following:  Build an enriched, correlated, and comprehensive view of internal entities (assets and users) and external entities (IOCs). Identify the relationships between these entities.
## Data sources for the ECG
The ECG combines data from the following sources:    Context source Source Description     Entity context Customer-provided Google SecOps directly ingests structured organizational data, such as authoritative details on users and assets, from external systems. These sources include Identity Providers (IDPs), Configuration Management Database (CMDB) systems (such as ServiceNow CMDB, Duo User Context), and vulnerability management systems.   Derived context Google SecOps-generated Google SecOps generates statistical data based on analysis of ingested activity. It enriches events and entities from various sources within your environment (for example, Windows AD, Azure AD, Okta, Google Cloud, IAM). For example:  Calculates and enriches each entity with a prevalence statistic that indicates its popularity in the environment. Calculates and enriches the entity first-seen-time and last-seen-time.    Global context Google-sourced Global sources provide internal and external threat intelligence and reputation data. For example:  Ingests and stores Google Threat Intelligence data. Enriches entities with information from Safe Browsing threat lists. Enriches entities with WHOIS data.
## ECG data processing pipeline
First, the UDM aliasing and enrichment pipeline ingests and normalizes raw security events into UDM structures. Note: "ECG merging" is not the same as "UDM aliasing". While UDM aliasing enriches events by adding identifiers (for example, mapping an IP address to a hostname within an event), ECG merges context from multiple sources (such as IdPs, CMDBs, and threat intelligence) to build a single profile for an entity.
Then, ECG merging builds a rich, authoritative profile for each entity by merging context from multiple origins (such as identity providers, Configuration Management Databases (CMDBs), threat intelligence feeds, and derived context) into a single, consolidated entity profile. ECG merging adds new connections, properties, and relationships to the ECG, and creates and updates derived context.
The ECG constructs both timed (temporal) and timeless (non-temporal) entities. The ECG evaluates timed entities within the specified rule and search time ranges, while it evaluates timeless entities without considering the time range of the search or rule.
The ECG merges context records by matching common key identifiers, such as `hostname`, `MAC address`, `user ID`, or `email address`, across these different data sources. It merges records that match across any of these values to build one comprehensive and enriched view of an entity.
ECG aliasing uses the following UDM fields as "merge keys":  `Asset`  `entity.asset.product_object_id` `entity.asset.hostname` `entity.asset.asset_id` `entity.asset.mac`  `User`  `entity.user.product_object_id` `entity.user.userid` `entity.user.windows_sid` `entity.user.email_addresses` `entity.user.employee_id`  `Resource`  `entity.resource.product_object_id` `entity.resource.name`  `Group`  `entity.group.product_object_id` `entity.group.email_addresses` `entity.group.windows_sid`
When there are conflicting values with any of the above fields during the merge process, the ECG pipeline will select the value with the latest start time for updating the entity.
The ECG creates entity-context data with a five-day look-back window. This process handles late-arriving data and creates an implicit time to live for entity-context data.
The ECG distinguishes between contextual data (assets, users, resources, groups) and indicators of compromise (IOCs).
### Example: Merging user data with ECG merging
Google SecOps ingests user data for `jdoe` from three sources: Okta, Azure AD, and a vulnerability scanner. ECG merges these three records based on matching identifiers (such as `jdoe@example.com`) to create one unified `jdoe` user entity in the ECG, containing attributes from all three sources.
### Example: Eliminating redundant data to create a common entity
To create a common combined entity, the ECG eliminates redundant data through deduplication. It does this by generating time intervals rather than matching exact timestamps.
For example, consider two entities `e1` and `e2` with timestamps `t1` and `t2`, respectively. If `e1` and `e2` are otherwise identical, the ECG deduplicates them by ignoring timestamp differences in the following fields:  `collected_timestamp` `creation_timestamp` `interval`  Note: If there are conflicts on non repeated fields, the data from the latest entity will be used.
## Critical entity and event context ECG data sources
Google SecOps requires several specific data sources to create and update entities.
### Critical entity context ECG data sources
Authoritative data sources for your environment's users and assets provide the most critical log data for building an entity data model. For example:
Category Critical data sources Entities populated     Identity and access management Active Directory, Azure AD, Okta, Google Cloud Identity `user`,`group`   Asset inventory CMDBs, JAMF, Microsoft Intune `asset`   Threat intelligence Custom or third-party feeds, Google Threat Intelligence (GTI) `ip_address`,`domain_name`,`file`
#### Example search
To list parsers that support each category:  Go to Supported log types with a default parser.
Type a category in the search bar, for example:  For parsers relevant to asset inventory, type `inventory` or `asset`. For parsers relevant to identity and access management, type `identity`. For parsers relevant to threat intelligence, type `IOC`.
### Data sources and critical UDM fields for entity profiling
Google SecOps enhances entity profiles based on authoritative entity context data sources and critical UDM fields:         Entity Type Data sources Critical UDM fields (for aliasing and indexing)     Process Endpoint logs provide the PSPI (`principal.process.product_specific_process_id`), a stable identifier crucial for robust process aliasing. Examples include CrowdStrike EDR (CS_EDR) and Windows Sysmon (WINDOWS_SYSMON). `source.process.product_specific_process_id`   User These sources provide user attributes and identity information. For example, Duo Entity context data (DUO_CONTEXT) and Okta (OKTA). `source.user.userid`, `source.user.email_address`, `source.user.windows_sid`, `source.user.product_object_id`   Asset or Endpoint These sources provide authoritative asset information. For example, ServiceNow CMDB (SERVICENOW_CMDB) and Tanium Asset (TANIUM_ASSET). `source.ip`, `source.hostname`, `source.asset_id`, `principal.asset.hostname`   File hash Provides a unique "digital fingerprint" of the data content to verify data integrity. `source.file.sha256`, `source.file.sha1`, `source.file.md5`
### Critical event context data UDM fields
Google SecOps requires several critical event context data UDM fields.
The most critical UDM fields are those that act as stable identifiers and relationship indicators (`principal.*`, `target.*`, `src_*`, and `dst_*` fields).
See the list of key UDM fields belonging to the `Entity graph` feature area.
To build a comprehensive ECG, prioritize data sources that contribute high-value identifiers and relationship data. For example:         Entity type Critical data sources Critical UDM fields for entity building     Asset (host) EDR and XDR, DNS and DHCP, Firewall, Google Cloud console Audit Logs  `metadata.event_type`, `principal.asset.asset_id`, `principal.asset.hostname`, `principal.ip`    User Identity Provider (IdP) logs, HR Feed (context), Cloud Identity Logs, Email Gateway  `principal.user.userid`, `principal.user.email_addresses`, `target.user.userid`, `principal.ip`    Network Firewall, VPN, DNS, VPC Flow Logs  `principal.ip`, `target.ip`, `src_ip`, `dst_ip`, `network.direction`    File and process EDR and XDR, Application Logs  `target.file.full_path`, `target.process.file.full_path`, `target.process.command_line`
#### Example
ECG data relies on these UDM fields to join ECG data and UDM event data in rules, searches, and dashboards.
For example, you can join user context data in a "brute force" monitoring rule to only alert if the implicated user is also part of the "Domain Admins" group and the implicated asset is a domain controller:
```
events:
  $fail.metadata.event_type = "USER_LOGIN"
  $fail.metadata.vendor_name = "Microsoft"
  $fail.principal.hostname = $hostname
  $fail.target.user.userid = $target_user
  $fail.security_result.action = "BLOCK"
  $fail.metadata.product_event_type = "4625"
 
  $fail.metadata.event_timestamp.seconds < $success.metadata.event_timestamp.seconds
 
  $success.metadata.event_type = "USER_LOGIN"
  $success.metadata.vendor_name = "Microsoft"
  $success.target.user.userid = $target_user
  $success.principal.hostname = $hostname
  $success.security_result.action = "ALLOW"
  $success.metadata.product_event_type = "4624"
  $user.graph.entity.user.userid = $target_user
  $user.graph.metadata.entity_type = "USER"
  $user.graph.metadata.source_type = "ENTITY_CONTEXT"
  any $user.graph.relations.entity.group.group_display_name = "Domain Admins"

  $asset.graph.entity.asset.hostname = $hostname
  $asset.graph.metadata.entity_type = "ASSET"
  $asset.graph.metadata.source_type = "ENTITY_CONTEXT"
  any $asset.graph.relations.entity.group.group_display_name = "Domain Controllers"
 
match:
  $target_user, $hostname over 15m
condition:
  #fail > 4 and $success and $user and $asset

```
## Derived context enrichments
Google SecOps generates dynamic event-driven inference data from your organization's event data for each entity across all namespaces. It uses alias information, data from internal enrichment processes, and security event data to establish relationships (for example, an `asset` using an `IP address`). This process adds valuable context to enhance entity profiles.
For example, it adds `entity.file.sha256` to `file (hash)` entities and `(principal or target).ip_geo_artifact.location.country_or_region` to `network (geolocation)` entities.
Google SecOps analyzes multiple indicators in ingested activity to enrich events with context information. It runs critical enrichment functions to generate, for example, entity rarity metrics such as prevalence statistics and temporal metrics such as `first-seen-time` and `last-seen-time`.
### Prevalence statistics
The ECG is also responsible for analyzing existing and incoming data to calculate and store prevalence metrics as a derived context field. These metrics represent a numeric "popularity" value for entities like `domain`, `file hash`, or `IP address` across your environment. This helps you spot rare or unusual activity, as more popular entities are usually less likely to be malicious.
Google SecOps updates these statistics regularly and stores them in a separate entity context. The detection engine can use these values, and you can search for them using UDM query syntax. However, the Console does not display these values with other entity details.
You can use the following fields when creating detection engine rules.    Entity type UDM fields     Domain `entity.domain.prevalence.day_count`  `entity.domain.prevalence.day_max`  `entity.domain.prevalence.day_max_sub_domains`  `entity.domain.prevalence.rolling_max`  `entity.domain.prevalence.rolling_max_sub_domains`   File (Hash) `entity.file.prevalence.day_count`  `entity.file.prevalence.day_max`  `entity.file.prevalence.rolling_max`   IP address `entity.artifact.prevalence.day_count`  `entity.artifact.prevalence.day_max`  `entity.artifact.prevalence.rolling_max`
Google SecOps calculates the `day_max` and `rolling_max` values differently, as follows:  `day_max` is the maximum prevalence score for the artifact during the day (a day is defined as 12:00:00 AM to 11:59:59 PM UTC). `rolling_max` is the maximum per-day prevalence score (that is, `day_max`) for the artifact over the previous 10-day window. The system uses `day_count` to calculate `rolling_max` and its value is always 10.
When the system calculates these values for a `domain`, the difference between `day_max` and `day_max_sub_domains` (and `rolling_max` versus `rolling_max_sub_domains`) is as follows:  `rolling_max` and `day_max` represent the number of daily unique internal IP addresses accessing a given domain (subdomains excluded). `rolling_max_sub_domains` and `day_max_sub_domains` represent the number of unique internal IP addresses accessing a given domain (subdomains included).
Google SecOps calculates prevalence statistics using newly ingested entity data. Google SecOps does not perform calculations retroactively on previously ingested data. It takes approximately 36 hours for Google SecOps to calculate and store the statistics. Caution: Including the `prevalence` argument can significantly increase the data queried, potentially leading to a Rule Error. If you encounter a Rule Error, refine your rule parameters. For example, add more filters or reduce the time range specified in the `match` section.
#### Example
The ECG requires these UDM fields to join the relevant context data into a rule or search. You must explicitly join all ECG-related data to UDM event data.
For example, you can use `prevalence` data in ECG to determine connections to "rare" domains in your security logs:
```
    $dns.metadata.event_type = "NETWORK_DNS"
    $dns.network.dns.questions.name != ""
    $dns.network.dns.questions.name = $domain
    $prevalence.graph.metadata.entity_type = "DOMAIN_NAME"
    $prevalence.graph.metadata.source_type = "DERIVED_CONTEXT"
    $prevalence.graph.entity.hostname = $domain
    $prevalence.graph.entity.domain.prevalence.day_count = 10
    $prevalence.graph.entity.domain.prevalence.rolling_max > 0
    $prevalence.graph.entity.domain.prevalence.rolling_max <= 3

  match:
    $domain over 5m
  condition:
    $dns and $prevalence

```
Note: Search and Dashboards support a maximum of one join, Rules support a maximum of two joins.Note: Including the `prevalence` argument can cause the search to query significantly more data.
### First-seen and last-seen times of entities
Google SecOps analyzes incoming data to enrich entity context records with the following critical fields:  `first-seen-time`: The date and time when the entity was first seen in your environment. `last-seen-time`: The date and time of the most recent observation.
These derived fields let you correlate activity across `domain`, `file hash`, `asset`, `user`, or `IP address` entities.
The system stores these values in the following UDM fields:    Entity type UDM fields     Domain `entity.domain.first_seen_time` `entity.domain.last_seen_time`   File (hash) `entity.file.first_seen_time` `entity.file.last_seen_time`   IP address `entity.artifact.first_seen_time` `entity.artifact.last_seen_time`   Asset `entity.asset.first_seen_time`   User `entity.user.first_seen_time`
#### Exceptions for first-seen-time and last-seen-time calculations:
For `asset` and `user` entities, Google SecOps only populates the `first_seen_time` field, but not the `last_seen_time` field. Google SecOps doesn't calculate the statistics for each entity within individual namespaces. Google SecOps doesn't export these statistics to the Google SecOps `events` schema in BigQuery. Google SecOps doesn't calculate these values for other entity types, such as a `group` or `resource`.
## Global context enrichments
These sources include external threat intelligence and reputation data from internal and third-party global sources.
### Ingest Google Threat Intelligence data
Google SecOps ingests data from Google Threat Intelligence (GTI) data sources and provides contextual information for investigating activity in your environment.
Query the following data sources:  GTI Tor Exit Nodes: IP addresses that are known Tor exit nodes. GTI Benign Binaries: Files that are either part of the original operating system distribution or were updated by an official operating system patch. Some official operating system binaries that have been abused by an adversary through activity common in living-off-the-land attacks are excluded from this data source, such as those focused on initial entry vectors. GTI Remote Access Tools: Files that have frequently been used by malicious actors. These tools are generally legitimate applications that are sometimes abused to remotely connect to compromised systems.
The system stores this contextual data globally as entities. You can query the data using detection engine rules. Include the following UDM fields and values in the rule to query these global entities:  `graph.metadata.vendor_name` = `Google Threat Intelligence` `graph.metadata.product_name` = `GTI Feed`  Note: In the following sections, replace the placeholder `<variable_name>` with the unique variable name you use in a rule to identify a UDM record.
#### Timed versus timeless Google Threat Intelligence data sources
Google Threat Intelligence data sources include timed or timeless types.
Each entry in timed data sources has an associated time range. If Google SecOps generates a detection on day 1, then on any day in the future, Google SecOps expects to generate the same detection for day 1 during a retrohunt.
Timeless data sources have no associated time range. This is because you only need to consider the latest dataset. The system typically uses timeless data sources for data that isn't expected to change, such as file hashes. If Google SecOps doesn't generate a detection on day 1, a detection might be generated for day 1 during a retrohunt on day 2 because a new entry was added to the timeless data source.
#### Data about Tor exit node IP addresses
Google SecOps ingests and stores IP addresses that are known Tor exit nodes. Tor exit nodes are points where traffic exits the Tor network. Tor exit node data is timed.
Google SecOps stores information ingested from this data source in the following UDM fields:        UDM field Description     `<variable_name>.graph.metadata.vendor_name` Stores the value `Google Threat Intelligence`.   `<variable_name>.graph.metadata.product_name` Stores the value `GTI Feed`.   `<variable_name>.graph.metadata.threat.threat_feed_name` Stores the value `Tor Exit Nodes`.   `<variable_name>.graph.entity.artifact.ip` Stores the IP address ingested from the GTI data source.
##### Example search
```
graph.metadata.source_type ="GLOBAL_CONTEXT"
graph.metadata.product_name = "GTI Feed"
graph.metadata.threat.threat_feed_name = "Tor Exit Nodes"

```
#### Data about benign operating system files
Google SecOps ingests and stores file hashes from the GTI Benign Binaries data source. Google SecOps stores information ingested from this data source in the following UDM fields. Benign binaries data is timeless.        UDM field Description     `<variable_name>.graph.metadata.vendor_name` Stores the value `Google Threat Intelligence`.   `<variable_name>.graph.metadata.product_name` Stores the value `GTI Feed`.   `<variable_name>.graph.metadata.threat.threat_feed_name` Stores the value `Benign Binaries`.   `<variable_name>.graph.entity.file.sha256` Stores the SHA256 hash value of the file.   `<variable_name>.graph.entity.file.sha1` Stores the SHA-1 hash value of the file.   `<variable_name>.graph.entity.file.md5` Stores the MD5 hash value of the file.
##### Example search
```
graph.metadata.source_type ="GLOBAL_CONTEXT"
graph.metadata.product_name = "GTI Feed"
graph.metadata.threat.threat_feed_name = "Benign Binaries"

```
#### Data about remote access tools
Remote access tools include file hashes for known remote access tools such as VNC clients that malicious actors have frequently used. These tools are generally legitimate applications that are sometimes abused to remotely connect to compromised systems. Google SecOps stores information ingested from this data source in the following UDM fields. Remote access tools data is timeless.        UDM field Description     `<variable_name>.graph.metadata.vendor_name` Stores the value `Google Threat Intelligence`.   `<variable_name>.graph.metadata.product_name` Stores the value `GTI Feed`.   `<variable_name>.graph.metadata.threat.threat_feed_name` Stores the value `Remote Access Tools`.   `<variable_name>.graph.entity.file.sha256` Stores the SHA256 hash value of the file.   `<variable_name>.graph.entity.file.sha1` Stores the SHA-1 hash value of the file.   `<variable_name>.graph.entity.file.md5` Stores the MD5 hash value of the file.
##### Example search
```
graph.metadata.source_type ="GLOBAL_CONTEXT"
graph.metadata.product_name = "GTI Feed"
graph.metadata.threat.threat_feed_name = "Remote Access Tools"

```
### Enrich entities with information from Safe Browsing threat lists
Google SecOps ingests data from Safe Browsing that is related to file hashes. Google SecOps stores the data for each file as an entity and provides additional context about the file. You can create detection engine rules that query this entity context data to build context-aware analytics. Note: Safe Browsing can only be used in rules, and the data is considered timeless.
Google SecOps stores the following information with the entity context record.        UDM field Description     `entity.metadata.product_entity_id` A unique identifier for the entity.   `entity.metadata.entity_type` This value is `FILE`, indicating that the entity describes a file.    `entity.metadata.collected_timestamp` The date and time that the entity was observed or the event occurred.   `entity.metadata.interval` Stores the start time and end time for which this data is valid. Because threat list content changes over time, the `start_time` and `end_time` reflect the time interval during which the data about the entity is valid. For example, a file hash was observed to be malicious or suspicious between `start_time` and `end_time`.   `entity.metadata.threat.category` The Google SecOps `SecurityCategory`. The system sets this to one or more of the following values:  `SOFTWARE_MALICIOUS`: indicates that the threat is related to malware. `SOFTWARE_PUA`: indicates that the threat is related to unwanted software.    `entity.metadata.threat.severity` This is the Google SecOps `ProductSeverity`. If the value is `CRITICAL`, this indicates that the artifact appears malicious. If the value isn't specified, there isn't enough confidence to indicate that the artifact is malicious.    `entity.metadata.product_name` Stores the value `Google Safe Browsing`.   `entity.file.sha256` The SHA256 hash value for the file.
#### Example rule
```
events:
    // find a process launch event, match on hostname
    $execution.metadata.event_type = "PROCESS_LAUNCH"
    $execution.target.process.file.sha256 != ""
    $execution.principal.hostname = $hostname

    // join execution event with Safe Browsing graph
    $sb.graph.entity.file.sha256 = $execution.target.process.file.sha256

    // look for files deemed malicious
    $sb.graph.metadata.entity_type = "FILE"
    $sb.graph.metadata.threat.severity = "CRITICAL"
    $sb.graph.metadata.product_name = "Google Safe Browsing"

  match:
    $hostname over 5m

  condition:
    $execution and $sb

```
### Enrich entities with WHOIS data
The system runs WHOIS data enrichment daily as a critical function. WHOIS data is both timed and timeless.
During ingestion of your device data, Google SecOps evaluates domains against WHOIS data. When domains match, Google SecOps stores the related WHOIS data with the domain's entity record. For each entity with `entity.metadata.entity_type = DOMAIN_NAME`, Google SecOps enriches it with WHOIS information.
Google SecOps populates enriched WHOIS data into the following fields in the entity record:  `entity.domain.admin.attribute.labels` `entity.domain.audit_update_time` `entity.domain.billing.attribute.labels` `entity.domain.billing.office_address.country_or_region` `entity.domain.contact_email` `entity.domain.creation_time` `entity.domain.expiration_time` `entity.domain.iana_registrar_id` `entity.domain.name_server` `entity.domain.private_registration` `entity.domain.registrant.company_name` `entity.domain.registrant.office_address.state` `entity.domain.registrant.office_address.country_or_region` `entity.domain.registrant.email_addresses` `entity.domain.registrant.user_display_name` `entity.domain.registrar` `entity.domain.registry_data_raw_text` `entity.domain.status` `entity.domain.tech.attribute.labels` `entity.domain.update_time` `entity.domain.whois_record_raw_text` `entity.domain.whois_server` `entity.domain.zone`
Google SecOps enriches `domain` entities (`entity.metadata.entity_type = "DOMAIN_NAME"`) with `registrant`, `creation`, and `expiration time` data from `global context` WHOIS records.
For descriptions of these fields, see the Unified Data Model field list document.
#### Example search
```
graph.metadata.source_type ="GLOBAL_CONTEXT"
graph.metadata.product_name = "WHOISXMLAPI Simple Whois"
graph.entity.domain.registry_data_raw_text != b""

```
### Best practices: Identify global context enriched data sources
To improve rule performance, include a filter in rules that use data from Global context enrichment sources to identify the specific enrichment type or source.
The following filter parameters identify the enrichment type or source: `entity_type`, `product_name`, and `vendor_name`.
For example, include the following filter fields in the `events` section of the rule that joins WHOIS data:
```
$enrichment.graph.metadata.entity_type = "DOMAIN_NAME"
$enrichment.graph.metadata.product_name = "WHOISXMLAPI Simple Whois"
$enrichment.graph.metadata.vendor_name = "WHOIS"

```
Note: Knowing the enrichment source can be as valuable as the data itself, and a single UDM field can have multiple enrichment sources. You can view this information in the Event Viewer or by using a UDM event search (for example, `principal.hostname="john.doe.desktop" metadata.event_type="NETWORK_CONNECTION"`).
## Entity Context Graph limitations and suggestions
When you use contextually enriched data, consider the following ECG behavior:  Don't add intervals to entity data; instead, let the ECG create intervals. This is because Google SecOps generates intervals during deduplication unless otherwise specified. If you specify the intervals, Google SecOps deduplicates only the same events and retains the most recent entity. To ensure that live rules and retrohunts work as expected, you must ingest entities at least once daily. If you don't ingest entities daily, but only once in two or more days, live rules might work as expected; however, retrohunts might lose some event contexts. If you ingest identical entities more than once daily, Google SecOps deduplicates them into a single entity. If event data is missing for a day, Google SecOps temporarily uses data from the previous day to ensure that live rules work correctly.
For details about general Google SecOps service limits, see Service limits.
## Related external content
Using Entity Graph as a Multi-dimensional List Aliasing in Chronicle SIEM Expiring IOCs in Entity Graph Google Safe Browsing in Chronicle SIEM