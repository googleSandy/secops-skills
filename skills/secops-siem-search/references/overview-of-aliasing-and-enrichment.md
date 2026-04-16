# Source: https://docs.cloud.google.com/chronicle/docs/event-processing/overview-of-aliasing-and-enrichment

#  UDM enrichment and aliasing overview
Supported in:    Google secops   SIEM
This document provides an overview of how Google Security Operations enriches raw logs after converting them to normalized Unified Data Model (UDM) events. Google SecOps provides different enrichment capabilities during ingestion and search.
## Enrichment during ingestion
UDM enrichment: Merges normalized data from context sources into UDM event sources to create a single enriched UDM event. These pipelines operate in near-real time and re-enrichment pipelines handle late-arriving data. Aliasing service: Keeps track of users and assets over time, merging multiple UDM Enrichment using aliasing to add context to a UDM indicator or event.
## Enrichment during search
Entity Context Graph (ECG): Combines customer log data, asset information, user identity, and multiple sources of threat intelligence to construct both timed and timeless entities and computed attributes (for example, prevalence, first seen, or last seen). Data tables: Act as lookup tables with defined columns. The data is stored in rows that are joined at query time with your UDM events. You can define the data in data tables and manage their lifecycle.
Aliasing, UDM enrichment, and ECG are derived from your parsed security data.
For more information on sources that can provide context data, see the following topics:  Ingest data using the entity data model Key UDM fields: Search for aliasing to view the important UDM fields.
## Supported aliasing and UDM enrichment capabilities
Google SecOps supports aliasing and enrichment for the following:  Assets Users Processes File hash metadata (VirusTotal) Geographic locations Cloud resources
## Supported ECG capabilities
Google SecOps supports the following ECG-related enrichments for search:  Prevalence First seen and last seen WHOIS data VirusTotal relationship data Tor exit node IP addresses Google Threat Intelligence IOCs Safe Browsing Threat lists
Enrichment during ingestion and search help you balance the trade-off between latency and accuracy for detections, searches, and dashboards. UDM enrichment and aliasing simplify the user experience by writing enrichments directly to UDM events. ECG and data tables provide flexibility and can be applied to specific use cases.