# SecOps SIEM: Enriched Data Field Reference

Google SecOps automatically enriches UDM events with geolocation and VirusTotal data.
These fields are queryable in UDM search alongside standard UDM fields.

Source: https://docs.cloud.google.com/chronicle/docs/investigation/use-enriched-data-in-search

---

## Geolocation Enrichment

Available on events containing **external IP addresses**. Fields are nested under
`ip_geo_artifact.location.*` on the relevant Noun namespace.

### Field paths

| Field | Example value |
|---|---|
| `<noun>.ip_geo_artifact.location.country_or_region` | `"Netherlands"` |
| `<noun>.ip_geo_artifact.location.state` | `"North Holland"` |
| `<noun>.ip_geo_artifact.location.city` | `"Amsterdam"` |
| `<noun>.location.region_latitude` | `52.520588` |
| `<noun>.location.region_longitude` | `4.788474` |

`<noun>` is `principal`, `target`, `src`, `about`, etc.

### Examples

**Search by country:**
```
target.ip_geo_artifact.location.country_or_region = "Netherlands" OR
principal.ip_geo_artifact.location.country_or_region = "Netherlands"
```

**Search by state:**
```
target.ip_geo_artifact.location.state = "North Holland" OR
principal.ip_geo_artifact.location.state = "North Holland"
```

**Search by coordinates:**
```
principal.location.region_latitude = 52.520588
principal.location.region_longitude = 4.788474
```

**Network connections to sanctioned/high-risk countries:**
```
metadata.event_type = "NETWORK_CONNECTION"
(
    target.ip_geo_artifact.location.country_or_region = "Cuba" OR
    target.ip_geo_artifact.location.country_or_region = "Iran" OR
    target.ip_geo_artifact.location.country_or_region = "North Korea" OR
    target.ip_geo_artifact.location.country_or_region = "Russia" OR
    target.ip_geo_artifact.location.country_or_region = "Syria"
)
```

**View geolocation in results:** The UDM grid displays `ip_geo_artifact` fields as
enriched columns alongside standard event fields.

---

## VirusTotal Enrichment

VirusTotal context is surfaced in two ways:
1. **UI**: Click "VT Context" on entity Overview panel (for domains, files, IPs)
2. **Query**: Use VirusTotal-enriched fields directly in UDM search

### File / PE enrichment fields

| Field | Description |
|---|---|
| `target.file.pe_file.imports.library` | DLL imported by PE file |
| `target.file.pe_file.imphash` | Import hash |
| `target.file.pe_file.compilation_time` | Compile timestamp |
| `target.file.md5` / `.sha1` / `.sha256` | File hashes |
| `target.file.mime_type` | File type (e.g. `"PE"`) |
| `target.file.file_type` | Enum (e.g. `FILE_TYPE_PE_EXE`) |
| `target.file.prevalence.rolling_max` | How many assets accessed this file (last N days) |

### File enrichment examples

**Find process loading a specific DLL:**
```
metadata.event_type = "PROCESS_MODULE_LOAD"
target.file.file_type = "FILE_TYPE_PE_EXE"
target.file.pe_file.imports.library = "kernel32.dll"
```

**Hunt for low-prevalence executables (rare files = potentially malicious):**
```
metadata.event_type = "PROCESS_LAUNCH"
principal.process.file.file_type = "FILE_TYPE_PE_EXE"
principal.process.file.prevalence.rolling_max < 5
```

### Domain enrichment fields

| Field | Description |
|---|---|
| `target.domain.prevalence.rolling_max` | Assets accessing this domain per day |
| `target.domain.first_seen_time` | First seen in environment |
| `target.domain.last_seen_time` | Last seen in environment |
| `target.domain.registrar` | Domain registrar name |
| `target.domain.creation_time` | Domain registration date |

### IP artifact enrichment fields

| Field | Description |
|---|---|
| `principal.artifact.prevalence.rolling_max` | Assets connecting to this IP per day |
| `principal.artifact.first_seen_time` | First seen in environment |
| `principal.artifact.last_seen_time` | Last seen in environment |
| `principal.artifact.asn` | Autonomous System Number |
| `principal.artifact.as_owner` | AS owner organization |
| `principal.artifact.regional_internet_registry` | RIR (ARIN, RIPE, etc.) |

---

## Enrichment Context Types

When viewing entity context aggregates, enrichment data is categorized as:
- **Entity Context** — ingested from customer data (AD, EDR, CMDB)
- **Derived Context** — calculated from customer telemetry (prevalence, first/last seen)
- **Global Context** — Google/VirusTotal global threat intelligence (WHOIS, Safe Browsing)
