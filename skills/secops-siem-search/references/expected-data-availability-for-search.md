# Source: https://docs.cloud.google.com/chronicle/docs/investigation/expected-data-availability-for-search

# Understand data availability for search
Supported in:    Google secops
This document details the data ingestion lifecycle, including end-to-end data flow and latency, and how these factors impact the availability of recently ingested data for querying and analysis.
## Ingest and process data in Google Security Operations
This section describes how Google SecOps ingests, processes, and analyzes security data.
### Data ingestion
The data ingestion pipeline begins by collecting your raw security data from sources such as:  Security logs from your internal systems Data stored in Cloud Storage Your Security Operations Center (SOC) and other internal systems
Google SecOps brings this data to the platform using one of its secure ingestion methods.
The primary ingestion methods are:
Direct Google Cloud ingestion
Google SecOps uses direct Google Cloud ingestion to automatically pull in logs and telemetry data from your organization's Google Cloud, including Cloud Logging, Cloud Asset Inventory metadata, and Security Command Center Premium findings.
Ingestion APIs
Send data directly to Google SecOps using its public REST Ingestion APIs. You use this method for custom integrations or to send data as either unstructured logs or pre-formatted Unified Data Model (UDM) events.
Bindplane agent
You can deploy the versatile Bindplane agent in your environment (on-premises or other clouds) to collect logs from a wide variety of sources and forward them to Google SecOps.
Data feeds
In Google SecOps, you configure data feeds to pull logs from third-party sources, such as specific third-party cloud storage buckets (like Amazon S3) or third-party APIs (like Okta or Microsoft 365).
### Normalization and data enrichment
Once data arrives in Google SecOps, the platform processes it through the following stages:
Parsing and normalization
A parser first processes raw log data to validate, extract, and transform the data from its original format into the standardized UDM. Parsing and normalization lets you analyze disparate data sources (for example, firewall logs, endpoint data, cloud logs) using a single, consistent schema. The original raw log remains stored alongside the UDM event.
Indexing
After normalization, Google SecOps indexes the UDM data to deliver fast query speeds across massive datasets, making the UDM events searchable.
UDM Aliasing and enrichment  Google SecOps performs UDM aliasing and enrichment to enrich UDM events with valuable context, by identifying and adding context data and indicators for log entities. For example, it connects a user's `login name` to their various `IP addresses`, `hostnames`, and `MAC addresses`. Geolocation: Google SecOps enriches IP addresses with geolocation data.
ECG enrichment
Google SecOps performs ECG aliasing which merges context from multiple sources (such as IdPs, CMDBs, and threat intelligence), to build a consolidated entity profile in the entity context graph.
Threat intelligence: Google SecOps automatically compares event data against Google's vast threat intelligence, including sources like VirusTotal and Safe Browsing, to identify known malicious threats, like `domains`, `IP addresses`, and `file hashes`.
WHOIS: Google SecOps enriches domain names with their public registration WHOIS information.
### Data availability for analysis
After being processed and enriched, UDM data is immediately available for analysis:
Real-time detection
The Detection Engine automatically runs Live Rule-enabled custom and Google-built rules against live incoming data to identify threats and generate alerts.
Search and investigation
An analyst can use the Search methods to search across all this normalized and enriched data. For example, using UDM search to pivot between related entities (like a `user`, to their `asset`, to a malicious `domain`), and investigate alerts.
## Search methods
Google SecOps provides several distinct methods for searching your data, each serving a different purpose.
### UDM search
UDM search is the primary and fastest search method, used for most investigations.  What it searches: It queries the normalized and indexed UDM events. Because all data is parsed into this standard format, you can write one query to find the same activity (like a login) across all your different products (for example, Windows, Okta, Linux). How it works: You use a specific syntax to query fields, operators, and values. Example: `principal.hostname = "win-server" AND target.ip = "10.1.2.3"`
### Raw log search
Use Raw log search to find something in the original, unparsed log message that may not have been mapped to a UDM field.  What it searches: It scans the original, raw text of the logs before they were parsed and normalized. This is useful for finding specific strings, command-line arguments, or other artifacts that aren't indexed UDM fields. How it works: You use the `raw =` prefix. It can be slower than UDM search because it doesn't search indexed fields. Example (String): `raw = "PsExec.exe"` Example (Regex): `raw = /admin\$/`
### Natural language search (Gemini)
Natural language search (Gemini) lets you use plain English to ask questions, which Gemini then translates into a formal UDM query.  What it searches: It provides a conversational interface to query UDM data. How it works: You type a question, and Gemini generates the underlying UDM search query for you, which you can then run or refine. Example: "Show me all failed logins from user 'bob' in the last 24 hours"
### SOAR search
SOAR search is specific to SOAR components. You use it to manage security incidents, not to hunt in logs.  What it searches: It searches for Cases and Entities (like users, assets, IP addresses) within the SOAR platform. How it works: You can use free-text or field-based filters to find cases by, for example, their ID, alert name, status, and assigned user. Example: Search for `CaseIds:180` or `AlertName:Brute Force`
## Data ingestion pipeline to search availability
The system processes newly ingested data through several steps. The duration of these steps determines when newly ingested data becomes available for querying and analysis.
The following table breaks down the processing steps for newly ingested data by search method. Newly ingested data becomes searchable after these steps are complete.   Search method Data being searched Processing steps contributing to availability time    UDM search Natural language search (Gemini)   Normalized and enriched UDM events   Ingestion: Log arrives at the Google SecOps ingestion point. Parsing: The raw log is identified and processed by its specific parser. Normalization: Data is extracted and mapped to the UDM schema. Indexing (UDM): The normalized UDM record is indexed for fast, structured search. Enrichment: Context (threat intelligence, geolocation, user or asset data) is added.     Raw log search Original, unparsed log text   Ingestion: Log arrives at the Google SecOps ingestion point.     SOAR search Cases and entities  This is a different lifecycle, as it searches for alerts and cases, not logs. The time is based on:  UDM event availability: Uses the same processing steps listed for "UDM search". Detection: A Detection Engine rule must match the UDM event(s). Alert generation: The system creates a formal alert from the detection. Case creation: The SOAR platform ingests the alert and creates a case.
## Example data flow
The following example demonstrates how Google SecOps ingests, processes, enhances, and analyzes your security data, making it available for searches and further analysis.
Example of data processing steps  Retrieves security data from cloud services like Amazon S3 or from the Google Cloud. Google SecOps encrypts this data in transit. Separates and stores your encrypted security data in your account. Access is limited to you and a small number of Google personnel for product support, development, and maintenance. Parses and validates raw security data, making it easier to process and view. Normalizes and indexes the data for quick searches. Stores the parsed and indexed data within your account. Enriches with context data.  Offers secure access for users to search and review their security data. Compares your security data with the VirusTotal malware database to identify matches. In a Google SecOps event view, such as the Asset view, click VT Context to see VirusTotal information. Google SecOps doesn't share your security data with VirusTotal.
### Examples of the expected time until Search availability
The expected time until the newly ingested data becomes available for Search is the sum of the flow durations along the data flow.
For example, a typical average time for data availability in UDM search is approximately 5 minutes and 30 seconds from when the data is sent to the Google SecOps ingestion service.    Data flow step Description Flow duration     Cloud Storage to Raw logs Ingests raw logs from Cloud Storage. Less than 30 seconds   Security logs to Data forwarding service Transmits security logs from internal systems to the platform. N/A   Data forwarding service to Raw logs Sends raw security data received from various sources to the ingestion pipeline. Less than 30 seconds   Raw logs to Parse and validate Parses and validates raw logs into the UDM format. Less than 3 minutes   Parse and validate to Index Indexes the parsed UDM data for fast searching. N/A   Index to Parsed customer data Makes the indexed data available as parsed customer data for analysis. Less than 2 minutes