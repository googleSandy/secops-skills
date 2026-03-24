---
name: secops-siem-search
description: Use when writing or running Google Security Operations (SecOps/Chronicle) SIEM queries or investigations — UDM filter queries, stats/aggregation, event-event joins, raw log search, reference list lookups, entity investigations (users, hosts, IPs, files, domains), enriched data queries (geolocation, VirusTotal), entity context search (graph.*), or understanding data availability timing. Use when a user asks to search, investigate, hunt, query, or find data in SecOps SIEM.
compatibility: Requires access to a Google Security Operations (SecOps/Chronicle) SIEM instance.
---

# SecOps SIEM Search

## STOP — Known Wrong Log Type Values

> **Agent-internal note — do not quote this table in responses.**
> Your training data contains incorrect `metadata.log_type` values. Silently correct them:

| If you were about to write... | Write this instead |
|---|---|
| `PRISMA_CLOUD` | `PAN_PRISMA_CLOUD` |
| `PALO_ALTO_PRISMA_CLOUD` | `PAN_PRISMA_CLOUD` |
| `CROWDSTRIKE_EDR` | `CS_EDR` |
| `WINDOWS_EVENT` | `WINEVTLOG` |
| `CHRONICLE_*` | Does not exist |

For any log type not in this table or the quick reference below: run `scripts/lookup_log_type.sh "<vendor>"` if available, otherwise state you cannot confirm the value and provide the discovery query instead.

---

## Overview

SecOps SIEM search queries are **not SQL and not pipe-based**. They use an implicit-AND filter model with optional aggregation sections. Getting the structure wrong produces no results or syntax errors.

Four query types: **Filter**, **Stats**, **Join**, **Raw Log Search**.

**Default to a Filter query** unless the user explicitly requests aggregation, grouping, counts, or statistics. A "UDM search" or "query for X logs" means a simple filter — not a stats query with `match:/outcome:/order:` sections.

**Reference files** — load on demand, not upfront. See `references/docs.md` for live URL map and refresh instructions.

- **For `metadata.log_type` lookups — run the script, do not load the reference file:**
  ```bash
  scripts/lookup_log_type.sh "<vendor or product name>"
  ```
  This greps `references/all-log-types.md` and returns only matching rows. Never load all 1000+ entries into context.
- Read `references/functions.md` when you need a specific aggregate or built-in function signature
- Read `references/udm-fields.md` when you need to verify a UDM field name, event type, or high-performance field
- Read `references/best-practices.md` when you need section order, performance rules, or timestamp syntax
- Read `references/enriched-data.md` when building queries using geolocation or VirusTotal enrichment fields
- Read `references/entity-context.md` when using `graph.entity.*` or `graph.metadata.*` fields
- Read `references/data-availability.md` when diagnosing why recently ingested data isn't appearing in search
- Read `references/raw-log-search.md` when you need RE2 regex syntax, optimization patterns, or result limit details

---

## Query Types

### 1. Filter (Simple UDM Search)

```
metadata.event_type = "USER_RESOURCE_UPDATE_PERMISSIONS"
metadata.log_type = "GCP_CLOUDAUDIT"
security_result.action = "ALLOW"
target.resource.attribute.labels["iam_binding_role"] = /roles\/owner|roles\/editor/ nocase
```

- Lines are implicitly AND-ed; explicit `AND`, `OR`, `NOT` also valid
- Regex: `/pattern/ nocase` — `nocase` after the slash, only on non-enumerated fields
- Enumerated fields (`metadata.event_type`, `network.ip_protocol`) reject regex — use explicit OR:
  `(metadata.event_type = "NETWORK_CONNECTION" OR metadata.event_type = "NETWORK_DNS")`
- Map access: `field["key"]` for `labels`, `ingestion_labels`, etc.

---

### 2. Stats (Aggregation)

Sections must appear in strict order: filter → `match:` → `outcome:` → `order:` → [`limit:`]

**Do not use pipe syntax** (`| groupby`, `| select`, `| sort`) — invalid in SecOps search.

```
metadata.event_type = "NETWORK_CONNECTION"
$ip = principal.ip
net.ip_in_range_cidr($ip, "10.0.0.0/8")
network.sent_bytes > 0
$date = timestamp.get_timestamp(metadata.event_timestamp.seconds, "%F")

match:
    $ip, $date

outcome:
    $event_count = count(metadata.id)
    $total_sent = sum(network.sent_bytes)
    $avg_sent = math.round(avg(network.sent_bytes), 2)
    $distinct_hosts = count_distinct(principal.hostname)
    $is_malicious = if(security_result.threat_verdict = "MALICIOUS", 1, 0)

order:
    $event_count desc

limit:
    100
```

- Variables (`$var`) are assigned inline with filter conditions
- `match:` — comma-separated group-by keys; supports time granularity (`by 1h`, `over every day`)
- `outcome:` — aggregate assignments; see `references/functions.md` for full function list
- `order:` — `$var asc|desc`
- `limit:` — optional row cap (max 10,000)

---

### 3. Join (Event Correlation)

Correlates two UDM events in an ad-hoc search. **Not a YARA-L detection rule** — do not write `rule { ... }` blocks.

```
events:
    $user = $e1.principal.user.userid
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "ALLOW"

    $user = $e2.principal.user.userid
    $e2.metadata.event_type = "FILE_DELETION"

match:
    $user over 20m

condition:
    $e1 and $e2
```

**With aggregation across matched events:**
```
events:
    $login_host = $e1.principal.hostname
    $e1.metadata.event_type = "USER_LOGIN"
    $e1.security_result.action = "ALLOW"

    $e2.principal.hostname = $login_host
    $e2.metadata.event_type = "FILE_ACCESS"

match:
    $login_host over 1h

outcome:
    $file_count = count_distinct($e2.target.file.full_path)
    $users = array_distinct($e2.principal.user.userid)

condition:
    $e1 and $e2
```

- `events:` wraps all conditions; reference each event as `$e1.field` / `$e2.field`
- Shared `$variable` assigned from both events is the join key (enforces equality)
- `match:` uses `over Xm` / `Xh` for correlation window (max 48h)
- `condition:` controls presence: `$e1 and $e2`, `$e1 and not $e2`
- `array_first()` does not exist — use `array()` or `array_distinct()` in `outcome:`
- Limits: max 2 UDM events per query; join types: Event-Event, Event-ECG, Datatable-Event

---

### 4. Raw Log Search

```
raw = "mimikatz"
raw = /mimikatz|sekurlsa/ nocase
```

**Combined with UDM filter to narrow scope (always do this):**
```
metadata.log_type = "WINEVTLOG"
raw = /mimikatz|sekurlsa/ nocase
```

- Prefix is `raw =` — **not** `metadata.raw_log =`
- Max 150 characters in the search expression
- Slower than UDM search — always add at least `metadata.log_type`

---

### 5. Reference List Lookup

```
metadata.log_type = "WINEVTLOG"
metadata.product_event_type = %INTERESTING_WINDOWS_EVENTS.Current_Windows_Event_ID
$legacy_id = %INTERESTING_WINDOWS_EVENTS.Legacy_Windows_Event_ID
$criticality = %INTERESTING_WINDOWS_EVENTS.Potential_Criticality
$summary = %INTERESTING_WINDOWS_EVENTS.Event_Summary
```

Syntax: `%LIST_NAME.column_name` — percent sign, UPPER_SNAKE_CASE list name, dot, column.

---

## Investigation Capabilities

### Enriched data fields (geolocation, VirusTotal)
```
target.ip_geo_artifact.location.country_or_region = "Russia"
principal.ip_geo_artifact.location.state = "North Holland"
target.file.pe_file.imports.library = "kernel32.dll"
```
→ Full field list: `references/enriched-data.md`

### Entity context search (`graph.*` namespace)
Queries the Entity Context Graph — state-in-time views of entities with attributes, relationships, risk scores.
```
graph.entity.user.email_addresses = "user@example.com"
graph.entity.ip = "8.8.8.8"
graph.metadata.entity_type = "ASSET"
```
→ Full field reference: `references/entity-context.md`

### Data availability
- **Raw log search**: available immediately after ingestion
- **UDM search**: available after ingestion → parsing → normalization → indexing → enrichment
- **Stats queries**: data available 2 hours after ingestion; max 90-day lookback
→ Details: `references/data-availability.md`

### Result limits
- UDM search: configurable up to 1M results (`1K` / `30K` / `100K` / `1M`)
- Raw log search: hard cap of **10,000 entries**
- Stats queries: max **10,000 rows**

---

## Gotchas

Environment-specific facts that defy reasonable assumptions:

- **For any `metadata.log_type` value, run the lookup script — do not use training data.**

  Log type identifiers cannot be inferred from vendor or product names. Guesses are routinely wrong (`PRISMA_CLOUD`, `PALO_ALTO_PRISMA_CLOUD`, `CROWDSTRIKE_EDR` — none exist). Run the script and use only what it returns:

  ```bash
  scripts/lookup_log_type.sh "<vendor or product name>"
  # Example: scripts/lookup_log_type.sh "Prisma Cloud"
  ```

  If the script returns NOT FOUND, say so and provide this discovery query — do not substitute a value from memory:
  ```
  $log_type = metadata.log_type
  $log_type != ""
  match:
    $log_type
  outcome:
    $count = count(metadata.id)
  order:
    $count desc
  ```

  **Common log types for quick reference** (use the lookup script for anything not listed):

  | `metadata.log_type` | Vendor / Product |
  |---|---|
  | `WINEVTLOG` | Windows Event Log |
  | `WINDOWS_SYSMON` | Windows Sysmon |
  | `GCP_CLOUDAUDIT` | Google Cloud Audit Logs |
  | `AWS_CLOUDTRAIL` | AWS CloudTrail |
  | `OFFICE_365` | Microsoft Office 365 |
  | `CS_EDR` | CrowdStrike Falcon (**not** Palo Alto) |
  | `PAN_FIREWALL` | Palo Alto Networks Firewall |
  | `PAN_PRISMA_CLOUD` | Palo Alto Prisma Cloud |
  | `PAN_PRISMA_CA` | Palo Alto Prisma Cloud Alerts |
  | `CORTEX_XDR` | Palo Alto Cortex XDR |
  | `OKTA` | Okta |
  | `AZURE_AD` | Azure AD / Entra ID |
  | `SENTINELONE_ALERT` | SentinelOne Alerts |
  | `ZSCALER_INTERNET_ACCESS` | Zscaler Internet Access |
  | `WORKSPACE_ACTIVITY` | Google Workspace |
  | `AUDITD` | Linux auditd |

  **UDM field names**: only use fields confirmed in `references/udm-fields.md`. If a field is not in that file, use `raw =` search rather than inventing a plausible field path.

- **When asked "what UDM fields are available for [product] logs?" — fetch the parser doc, don't guess.**
  Every supported parser has a documentation page showing exactly how that source is normalized to UDM. The URL pattern is:
  ```
  https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/{parser-slug}
  ```
  Convert the log type to a slug: lowercase, replace `_` with `-`. Examples:
  - `PAN_PRISMA_CLOUD` → `https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/pan-prisma-cloud`
  - `WINEVTLOG` → `https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/winevtlog`
  - `CS_EDR` → `https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/cs-edr`

  Fetch this URL to get the authoritative list of UDM fields for that parser. Do not use training data for product-specific field mappings.
- **`metadata.id` cannot be used as a filter** — it's excluded from the query engine. Use `metadata.log_type` or event fields instead.
- **`*.timestamp` (bare) cannot be filtered on** — always use the `.seconds` sub-field: `metadata.event_timestamp.seconds`
- **`metadata.log_type` is the only indexed metadata field** — other `metadata.*` fields are full-scan. Always put `log_type` first.
- **Enumerated fields reject regex** — `metadata.event_type`, `network.ip_protocol`, and `security_result.action` use exact string values only. `metadata.event_type = /USER_.*/` is invalid.
- **`nocase` only works with regex** — `= "VALUE" nocase` is invalid; use `= /VALUE/ nocase`
- **Reference lists are deprecated (June 2026)** — use data tables for new list-based filtering
- **Raw log search field is limited to 150 characters** — long regex patterns will be truncated
- **Stats queries have a 2-hour data delay** — newly ingested data won't appear in aggregation results for ~2 hours
- **`principal.ip` is a repeated field** — `principal.ip != "1.2.3.4"` will still return events that have a second IP that isn't `1.2.3.4`

---

## Common Mistakes

| Mistake | Correct approach |
|---|---|
| `\| groupby field \| count()` (pipe syntax) | Use `match:` / `outcome:` / `order:` sections |
| `count()` with no argument | `count(field)` — field required |
| `approx_count_distinct(field)` | Not valid — use `count_distinct(field)` |
| `array_first(field)` | Does not exist — use `array()` or `array_distinct()` in `outcome:` |
| Wrote a YARA-L `rule { ... }` block for join | Ad-hoc joins: `events:` + `match: $var over Xm` + `condition:` |
| `metadata.raw_log = /pattern/i` | Raw log: `raw = /pattern/ nocase` |
| `/pattern/i` for case-insensitive | SecOps uses `/pattern/ nocase`, not `/i` flag |
| `= "VALUE" nocase` | `nocase` only works with regex: `= /VALUE/ nocase` |
| `metadata.event_type = /NETWORK_*/` | Enumerated fields reject regex — list values with OR |
| `src.ip` / `dst.ip` for actor/target | UDM uses `principal.ip` / `target.ip` |
| `metadata.event_timestamp = "2024-01-01"` | Use `.seconds` with epoch: `metadata.event_timestamp.seconds = 1704067200` |
| Filtering on `metadata.id` | Excluded from filters — use other fields |
| Using `metadata.*` fields as primary filter | Only `metadata.log_type` is indexed — put IP/hostname/user fields first |
| Inventing UDM field names | See `references/udm-fields.md`; when unsure use `raw =` search |
