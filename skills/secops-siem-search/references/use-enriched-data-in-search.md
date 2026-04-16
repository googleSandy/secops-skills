# Source: https://docs.cloud.google.com/chronicle/docs/investigation/use-enriched-data-in-search

# Use context-enriched data in search
Supported in:    Google secops   SIEM
To enable security analysts during an investigation, Google Security Operations ingests contextual data from different sources, normalizes the ingested data, and provides additional context about artifacts in a customer environment. This document provides examples of how analysts can use contextually-enriched data in search.
For more information about data enrichment, see How Google SecOps enriches event and entity data.
## Use VirusTotal-enriched metadata fields in search
The following example finds a process module that loads a `kernel32.dll` file into a particular process.
```
metadata.event_type = "PROCESS_MODULE_LOAD" AND
target.file.file_type = "FILE_TYPE_PE_EXE" AND
target.file.pe_file.imports.library = "kernel32.dll"

```
## Use geolocation-enriched fields in search
Google SecOps enriches events containing external IP addresses with geolocation data. This provides additional context during an investigation. This document explains how you can use geolocation-enriched fields when performing investigative searches.
Geolocation-enriched UDM fields can be accessed through search as shown in the following examples:
#### Search by country name (country_or_region)
```
target.ip_geo_artifact.location.country_or_region = "Netherlands" OR
principal.ip_geo_artifact.location.country_or_region = "Netherlands"

```
#### Search by state
```
target.ip_geo_artifact.location.state = "North Holland" OR
principal.ip_geo_artifact.location.state = "North Holland"

```
#### Search by longitude and latitude
```
principal.location.region_latitude = 52.520588 AND principal.location.region_longitude = 4.788474

```
#### Search by unauthorized target geographies
```
metadata.event_type = "NETWORK_CONNECTION" AND
(
    target.ip_geo_artifact.location.country_or_region = "Cuba" OR
    target.ip_geo_artifact.location.country_or_region = "Iran" OR
    target.ip_geo_artifact.location.country_or_region = "North Korea" OR
    target.ip_geo_artifact.location.country_or_region = "Russia" OR
    target.ip_geo_artifact.location.country_or_region = "Syria"
)

```
#### Search by Autonomous System Number (ASN)
```
metadata.event_type = "NETWORK_CONNECTION" AND
(
    target.ip_geo_artifact.network.asn = 33915
)

```
#### By organization name
```
metadata.event_type = "NETWORK_CONNECTION" AND
(
    target.ip_geo_artifact.network.organization_name = "google"
)

```
#### By carrier name
```
metadata.event_type = "NETWORK_CONNECTION" AND
(
    target.ip_geo_artifact.network.carrier_name = "google llc"
)

```
#### By DNS domain
```
metadata.event_type = "NETWORK_CONNECTION" AND
(
    target.ip_geo_artifact.network.dns_domain = "lightower.net"
)

```
## View geolocation-enriched fields in the UDM grid
Geolocation-enriched fields are displayed in UDM grid views including those in Search, Detection View, User View, and Event Viewer.