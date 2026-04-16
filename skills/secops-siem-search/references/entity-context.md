# SecOps SIEM: Entity Context Search Reference

Entity Context Search queries the **Entity Context Graph (ECG)** — a separate data model
from UDM events. It holds state-in-time views of entities (users, assets, domains, IPs,
files) with their attributes, relationships, and risk scores.

Source: https://docs.cloud.google.com/chronicle/docs/investigation/entity-context-in-search

---

## Field Namespaces

| Namespace | Purpose |
|---|---|
| `graph.entity.*` | Entity attributes (hostname, IP, user info, file hash, etc.) |
| `graph.metadata.*` | Entity metadata (type, product name, source, timestamps) |

**Note:** Autocomplete requires `graph.entity` or `graph.metadata` as prefix — `graph` alone shows no suggestions.

---

## Common Entity Field Paths

### Identity / asset fields
```
graph.entity.hostname
graph.entity.ip
graph.entity.mac
graph.entity.user.email_addresses
graph.entity.user.userid
graph.entity.user.user_display_name
graph.entity.user.department
graph.entity.user.title
graph.entity.user.first_name
graph.entity.user.last_name
graph.entity.asset.hostname
graph.entity.asset.ip
```

### File / hash fields
```
graph.entity.file.md5
graph.entity.file.sha256
graph.entity.file.full_path
graph.entity.file.mime_type
```

### Domain fields
```
graph.entity.domain.name
graph.entity.domain.registrar
graph.entity.domain.creation_time
```

### Metadata fields
```
graph.metadata.entity_type
graph.metadata.product_name
graph.metadata.source_type
graph.metadata.vendor_name
graph.metadata.collected_timestamp
```

---

## Entity Types (`graph.metadata.entity_type`)

Enumerated — use exact string values:

| Value | Represents |
|---|---|
| `"ASSET"` | Workstation, laptop, server, VM |
| `"USER"` | User account |
| `"IP_ADDRESS"` | External IP address |
| `"DOMAIN_NAME"` | Domain |
| `"FILE"` | File or hash |
| `"GROUP"` | User group |
| `"RESOURCE"` | Cloud resource |
| `"URL"` | URL |
| `"MUTEX"` | Mutex |

---

## Example Queries

**Find context for a specific user:**
```
graph.entity.user.email_addresses = "user@example.com"
```

**Find context for a user from a specific product:**
```
graph.entity.user.email_addresses = "user@example.com"
graph.metadata.product_name = "Google Cloud Compute Context"
```

**Find all entity context for a hostname:**
```
graph.entity.hostname = "server-01"
```

**Find all USER entities:**
```
graph.metadata.entity_type = "USER"
```

**Find asset by IP:**
```
graph.entity.ip = "10.1.2.3"
graph.metadata.entity_type = "ASSET"
```

**Find threat intelligence for an IP:**
```
graph.entity.ip = "8.8.8.8"
graph.metadata.source_type = "GLOBAL_CONTEXT"
```

---

## Timed vs Timeless Entities

| Type | Description | Examples |
|---|---|---|
| **Timed** | Valid over a time interval `(start_time, end_time)` | AD user records, asset inventory |
| **Timeless** | No expiry — always current | IoC threat intelligence, VirusTotal data |

In the Entity tab, timed and timeless entities are displayed in separate sub-tabs.

When using `graph.metadata.interval` for timed entities with time granularity in `match:`,
the `first` keyword applies only the interval start time.

---

## Source Types (`graph.metadata.source_type`)

| Value | Meaning |
|---|---|
| `"ENTITY_CONTEXT"` | Ingested from customer (AD, EDR, CMDB) |
| `"DERIVED_CONTEXT"` | Calculated from customer telemetry (prevalence, first/last seen) |
| `"GLOBAL_CONTEXT"` | Google/VT global intel (WHOIS, Safe Browsing, threat feeds) |

---

## Investigation Workflow: Compromised User

```
// Step 1: Get all context for the user
graph.entity.user.email_addresses = "user@example.com"

// Step 2: Filter to specific product context
graph.entity.user.email_addresses = "user@example.com"
graph.metadata.product_name = "Google Cloud Compute Context"

// Step 3: Correlate with UDM events (in separate search)
principal.user.email_addresses = "user@example.com"
metadata.event_type = "USER_LOGIN"
```

In the Overview tab, check:
- `First Seen Hour` / `Last Seen Hour` (IoCs and artifacts only)
- Associated hostnames, IPs, MACs
- Hardware model, OS platform, platform version

---

## Access Control

Entity Context data respects **Data Access Controls** — users only see entity data
within their authorized data access labels and scopes. If entity context is empty for
a query, check whether the data is within the user's access scope.
