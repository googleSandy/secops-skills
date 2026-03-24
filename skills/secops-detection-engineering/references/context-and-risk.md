# Detection Engineering: Context-Aware Analytics & Risk Scoring

Sources:
- https://docs.cloud.google.com/chronicle/docs/detection/context-aware-analytics
- https://docs.cloud.google.com/chronicle/docs/detection/yara-l-entity-risk-score
- https://docs.cloud.google.com/chronicle/docs/detection/risk-based-alerting

---

## Entity Graph in Rules

Rules can join UDM events with entity context data from the Entity Context Graph (ECG).

### Source Prefixes

```yara
// UDM event (default — 'udm' prefix optional)
$e1.metadata.event_type = "USER_LOGIN"
$e1.udm.metadata.event_type = "USER_LOGIN"   // explicit, equivalent

// Entity context graph (explicit 'graph' prefix required)
$e2.graph.entity.hostname = $hostname
$e2.graph.metadata.entity_type = "ASSET"
```

### Rules for Entity Joins

- Multi-event rules **must include at least one UDM event** — cannot join entity-only
- Entity data (`graph.*`) can join with UDM data via shared placeholder variables
- Entity context is valid: Multiple event rules, entity vs entity comparison,
  entity vs UDM comparison, repeated fields, sliding windows

### Common Entity Fields in Rules

```yara
// Asset context
$ctx.graph.entity.hostname = $host
$ctx.graph.entity.asset.ip = $ip
$ctx.graph.metadata.entity_type = "ASSET"

// User context
$ctx.graph.entity.user.email_addresses = $email
$ctx.graph.entity.user.department = "Finance"
$ctx.graph.entity.resource.attribute.roles.type = "ADMINISTRATOR"

// Relations
$ctx.graph.entity.relations.relationship = "OWNS"
$ctx.graph.entity.relations.entity_type = "USER"
```

---

## Context-Aware Rule Examples

### Admin Login/Logout Detection

```yara
rule LoginLogout {
  meta:
    description = "Login or logout by an administrator account"
    severity    = "MEDIUM"

  events:
    ($log_inout.metadata.event_type = "USER_LOGIN" or
     $log_inout.metadata.event_type = "USER_LOGOUT")
    $log_inout.principal.user.user_display_name = $user

    // Join entity context to check admin role
    $context.graph.entity.user.user_display_name = $user
    $context.graph.entity.resource.attribute.roles.type = "ADMINISTRATOR"

  match:
    $user over 2m

  condition:
    $log_inout and $context
}
```

### Sliding Window with Entity Context

```yara
rule EntityEventCorrelation {
  meta:
    severity = "HIGH"

  events:
    // Entity as pivot
    $e1.graph.entity.hostname = $host

    // UDM event correlated after entity
    $e2.udm.principal.hostname = $host
    $e2.udm.metadata.event_type = "PROCESS_LAUNCH"

  match:
    $host over 1h after $e1   // $e1 is graph entity, $e2 is UDM

  condition:
    $e1 and $e2
}
```

---

## Risk Score Rules

### Access Entity Risk Score

```yara
rule EntityRiskScore {
  meta:
    description = "Alert on entities with risk score > 100 in 24h window"
    severity    = "HIGH"

  events:
    $e1.principal.hostname != ""
    $e1.principal.hostname = $hostname

    // Join entity risk score
    $e2.graph.entity.hostname = $hostname
    $e2.graph.risk_score.risk_window_size.seconds = 86400   // 24h
    $e2.graph.risk_score.risk_score >= 100

  match:
    $hostname over 5m

  condition:
    $e1 and $e2
}
```

**Risk score fields:**
```yara
$e.graph.risk_score.risk_score                    // raw risk score (float)
$e.graph.risk_score.normalized_risk_score         // normalized 0-1000
$e.graph.risk_score.risk_window_size.seconds      // window size in seconds
$e.graph.risk_score.detections_count              // detections contributing to score
$e.graph.risk_score.first_detection_time          // first detection timestamp
$e.graph.risk_score.last_detection_time           // last detection timestamp
```

### Set Risk Score on a Detection

```yara
outcome:
  $risk_score = 75                          // assign risk to the detection
  $risk_entity_to_score = $e.principal.ip   // which entity gets the score
```

### ENTITY_RISK_CHANGE Rules

Detect changes in entity risk posture (risk threshold crossed):

```yara
rule HighRiskEntityChange {
  meta:
    severity = "HIGH"

  events:
    $e.metadata.event_type = "ENTITY_RISK_CHANGE"
    $e.about.hostname = $host
    $e.about.risk_score.normalized_risk_score >= 700

  condition:
    $e
}
```

`ENTITY_RISK_CHANGE` events are generated automatically when an entity's risk score
crosses configured thresholds. The affected entity is in the `about` field.

---

## Additional Qualifiers for Entity Context

When writing entity context rules, you can add qualifiers to filter the type and
source of entity context:

```yara
// Filter by entity type
$ctx.graph.metadata.entity_type = "USER"

// Filter by context source type
$ctx.graph.metadata.source_type = "ENTITY_CONTEXT"    // customer ingested
$ctx.graph.metadata.source_type = "GLOBAL_CONTEXT"    // Google/VT global intel
$ctx.graph.metadata.source_type = "DERIVED_CONTEXT"   // calculated from telemetry

// Filter by product
$ctx.graph.metadata.product_name = "Microsoft Active Directory"
```

---

## Safe Browsing Integration in Rules

Global entity data includes Google Safe Browsing SHA-256 file hashes — classified as Malware
or Unwanted Software. **No import required** — available to all SecOps instances, refreshed twice daily.
Contains only high-confidence malicious hashes (not borderline or suspicious).

```yara
rule google_safebrowsing_file_process_creation {
  meta:
    author      = "Google Cloud Security"
    description = "Process/file events matching Safe Browsing malicious hashes"
    severity    = "Critical"

  events:
    ($execution.metadata.event_type = "PROCESS_LAUNCH" or
     $execution.metadata.event_type = "FILE_CREATION")
    $execution.principal.hostname = $hostname
    $execution.target.process.file.sha256 = $sha256

    // Join to Safe Browsing global entity context
    $safebrowse.graph.entity.file.sha256 = $sha256
    $safebrowse.graph.metadata.product_name = "Google Safe Browsing"
    $safebrowse.graph.metadata.entity_type  = "FILE"
    $safebrowse.graph.metadata.source_type  = "GLOBAL_CONTEXT"

    // Optional: narrow to specific severity/category
    $safebrowse.graph.metadata.threat.category = "SOFTWARE_MALICIOUS"
    $safebrowse.graph.metadata.threat.severity  = "CRITICAL"

  match:
    $hostname over 1h

  condition:
    $execution and $safebrowse
}
```

**Key fields for Safe Browsing:**
- `graph.metadata.product_name = "Google Safe Browsing"`
- `graph.metadata.entity_type = "FILE"`
- `graph.metadata.source_type = "GLOBAL_CONTEXT"` (no need to also set this if product_name is set, but good practice)
- Join via `graph.entity.file.sha256 = $sha256`

---

## MISP / Threat Intelligence IOC Rules

When threat intelligence (MISP, STIX, Anomali, etc.) is ingested into the entity graph,
build rules that join UDM events to IOC entity context.

```yara
rule ioc_domain_C2 {
  meta:
    author      = "Google Cloud Security"
    description = "DNS events communicating to a C2 domain from MISP threat intel"

  events:
    // UDM event: DNS query
    $dns.metadata.event_type = "NETWORK_DNS"
    $dns.network.dns.questions.name = $dns_query

    // Entity graph: MISP IOC
    $ioc.graph.metadata.product_name  = "MISP"
    $ioc.graph.metadata.entity_type   = "DOMAIN_NAME"
    $ioc.graph.metadata.source_type   = "ENTITY_CONTEXT"
    // Optional: narrow to a specific threat category
    $ioc.graph.metadata.threat.summary = "C2 domains"
    $ioc.graph.entity.hostname          = $dns_query   // join key

  match:
    $dns_query over 5m

  condition:
    $dns and $ioc
}
```

**Key fields for ingested threat intel:**
- `graph.metadata.source_type = "ENTITY_CONTEXT"` for customer-ingested indicators
- `graph.metadata.entity_type` — `"DOMAIN_NAME"`, `"IP_ADDRESS"`, `"FILE"`, `"URL"`, `"MUTEX"`
- `graph.metadata.product_name` — your TI source name (e.g., `"MISP"`, `"Anomali"`)
- `graph.metadata.threat.summary` — optional, narrow to specific threat category
- Join via `graph.entity.hostname` (domains), `graph.entity.ip` (IPs), `graph.entity.file.sha256` (hashes)

**Note:** Whenever you join UDM events to entity graph data (including IOCs), the rule is
treated as a **multi-event rule** requiring a `match:` section.

---

## graph_exclude and graph_override (setup: section)

The `setup:` section (before `events:`) lets you pre-filter entity graph data using
data tables — useful for allowlisting or overriding entity values.

### graph_exclude — Allowlist Entities

Exclude entities that exist in a data table from rule evaluation:

```yara
rule utilities_associated_with_ntdsdit_entity_graph {
  meta:
    severity    = "High"
    description = "Detects ntds-related process launches, excluding subsidiary users"

  setup:
    // Exclude users in the subsidiary_users data table from this rule
    graph_exclude($graph.graph.entity.user.userid = %subsidiary_users.userid)

  events:
    $process.metadata.event_type = "PROCESS_LAUNCH"
    (
      re.capture($process.principal.process.file.full_path, /.*\\(.*).exe/) in %ntds_suspicious_processes or
      re.capture($process.target.process.file.full_path, /.*\\(.*).exe/) in %ntds_suspicious_processes
    )
    $process.principal.user.userid = $userid

    $graph.graph.metadata.entity_type  = "USER"
    $graph.graph.metadata.source_type  = "ENTITY_CONTEXT"
    $graph.graph.entity.user.userid    = $userid

  match:
    $userid over 5m

  condition:
    $process and $graph
}
```

**How graph_exclude works:** If a user's `userid` is in the `subsidiary_users` data table,
that user is excluded from the entity graph population — the rule won't fire for them.

### graph_override — Override Entity Values with Data Table Values

Replace entity graph field values with values from a data table:

```yara
setup:
  graph_override($graph.graph.entity.user.department = %user_classifications.department
                 WHERE $graph.graph.entity.user.userid = %user_classifications.userid)
```

**Note:** Reference lists are deprecated — use data tables instead for all list-based filtering.
