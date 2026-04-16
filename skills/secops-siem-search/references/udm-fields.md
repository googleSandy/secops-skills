# SecOps SIEM Search: UDM Field Reference

**Authoritative source:** https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list
Fetch that URL for field definitions not listed here. Do not invent field names.

---

## UDM Namespaces (Top-Level)

| Namespace | Purpose |
|---|---|
| `metadata.*` | Event metadata (timestamp, source, log type, event type) |
| `principal.*` | Actor / source entity initiating the action |
| `target.*` | Target entity being acted upon |
| `src.*` | Source entity (alternative to principal for some log types) |
| `about.*` | Additional referenced entities (e.g. attached files, embedded URLs) |
| `intermediary.*` | Intermediary entities (proxy, relay) |
| `observer.*` | Observer/sensor that reported the event |
| `network.*` | Network-level details (DNS, HTTP, DHCP, TLS, bytes) |
| `security_result.*` | Security verdict, action, category, threat info |
| `extensions.*` | Event-specific extensions (auth, vulns) |

---

## metadata Fields

| Field | Type | Notes |
|---|---|---|
| `metadata.event_type` | enum | Normalized event category — see full list below |
| `metadata.log_type` | string | Log source type (e.g. `"WINEVTLOG"`, `"GCP_CLOUDAUDIT"`) — **indexed** |
| `metadata.product_event_type` | string | Vendor-specific event name |
| `metadata.product_name` | string | Product that generated the event |
| `metadata.vendor_name` | string | Vendor name |
| `metadata.event_timestamp` | Timestamp | Use `.seconds` sub-field for filtering |
| `metadata.event_timestamp.seconds` | int64 | Unix epoch seconds — use for filtering |
| `metadata.ingested_timestamp.seconds` | int64 | When SecOps received the event |
| `metadata.ingestion_labels["key"]` | string | User-configured ingestion metadata |
| `metadata.description` | string | Human-readable event description |
| `metadata.id` | bytes | **Cannot be used as filter** |
| `metadata.product_log_id` | string | **Cannot be used as filter** |

---

## Noun Fields (principal / target / src / about / intermediary / observer)

All Noun namespaces share the same field structure:

| Field | Type | Notes |
|---|---|---|
| `<noun>.hostname` | string | Hostname or domain — **indexed** |
| `<noun>.ip` | string (repeated) | IP address list — **indexed**, repeated field |
| `<noun>.mac` | string (repeated) | MAC address list — **indexed** |
| `<noun>.port` | int32 | Port number |
| `<noun>.nat_ip` | string (repeated) | NAT-translated IPs |
| `<noun>.namespace` | string | AD forest / network namespace |
| `<noun>.administrative_domain` | string | Windows domain |
| `<noun>.platform` | enum | WINDOWS, LINUX, MAC, ANDROID, IOS, CHROME_OS |
| `<noun>.application` | string | Application or service name |
| `<noun>.url` | string | URL |
| `<noun>.labels` | Label (repeated) | Key-value labels: `<noun>.labels["key"]` |

### user sub-fields

| Field | Notes |
|---|---|
| `<noun>.user.userid` | User ID — **indexed** |
| `<noun>.user.email_addresses` | Email — **indexed** |
| `<noun>.user.windows_sid` | Windows SID — **indexed** |
| `<noun>.user.product_object_id` | Vendor GUID — **indexed** |
| `<noun>.user.user_display_name` | Display name |
| `<noun>.user.first_name` / `.last_name` | Name fields |
| `<noun>.user.department` | Department (repeated) |
| `<noun>.user.title` | Job title |
| `<noun>.user.account_type` | DOMAIN_ACCOUNT_TYPE, LOCAL_ACCOUNT_TYPE, SERVICE_ACCOUNT_TYPE, CLOUD_ACCOUNT_TYPE |

### process sub-fields

| Field | Notes |
|---|---|
| `<noun>.process.pid` | Process ID |
| `<noun>.process.command_line` | Full command line |
| `<noun>.process.file.full_path` | Executable path |
| `<noun>.process.file.md5` / `.sha1` / `.sha256` | File hashes — **indexed** |
| `<noun>.process.file.names` | File name list |
| `<noun>.process.parent_process.pid` | Parent PID |
| `<noun>.process.parent_process.file.full_path` | Parent executable path |
| `<noun>.process.parent_process.file.md5` / `.sha1` / `.sha256` | Parent hashes — **indexed** |

### file sub-fields

| Field | Notes |
|---|---|
| `<noun>.file.full_path` | Full file path |
| `<noun>.file.md5` / `.sha1` / `.sha256` | Hashes — **indexed** |
| `<noun>.file.mime_type` | MIME type (e.g. `"PE"`, `"PDF"`) |
| `<noun>.file.size` | Size in bytes |
| `<noun>.file.names` | File names (repeated) |

### group sub-fields

| Field | Notes |
|---|---|
| `<noun>.group.group_display_name` | Group display name (e.g. `"Domain Admins"`) |
| `<noun>.group.windows_sid` | Windows SID |
| `<noun>.group.product_object_id` | Vendor GUID |
| `<noun>.group.email_addresses` | Group email (repeated) |

### asset sub-fields

| Field | Notes |
|---|---|
| `<noun>.asset.hostname` | Asset hostname — **indexed** |
| `<noun>.asset.ip` | Asset IPs — **indexed** |
| `<noun>.asset.mac` | Asset MACs — **indexed** |

### resource sub-fields

| Field | Notes |
|---|---|
| `<noun>.resource.name` | Full resource name |
| `<noun>.resource.resource_type` | Type enum (STORAGE_BUCKET, VIRTUAL_MACHINE, etc.) |
| `<noun>.resource.resource_subtype` | Sub-type string |
| `<noun>.resource.attribute.labels["key"]` | Resource labels |
| `<noun>.resource.attribute.cloud.project.name` | Cloud project name |

### registry sub-fields

| Field | Notes |
|---|---|
| `<noun>.registry.registry_key` | Registry key path |
| `<noun>.registry.registry_value_name` | Value name |
| `<noun>.registry.registry_value_data` | Value data |

---

## network Fields

| Field | Notes |
|---|---|
| `network.sent_bytes` | Bytes sent |
| `network.received_bytes` | Bytes received |
| `network.sent_packets` | Packets sent |
| `network.received_packets` | Packets received |
| `network.ip_protocol` | TCP, UDP, ICMP, etc. (enumerated — no regex) |
| `network.application_protocol` | HTTP, DNS, SMTP, etc. (enumerated — no regex) |
| `network.direction` | INBOUND, OUTBOUND, BROADCAST |
| `network.session_id` | Session identifier |
| `network.dns.questions.name` | DNS query name — **indexed** |
| `network.dns.questions.type` | Query type (int) |
| `network.dns.response_code` | DNS response code |
| `network.dns.answers.data` | DNS answer data |
| `network.http.method` | HTTP method (GET, POST, etc.) |
| `network.http.response_code` | HTTP status code |
| `network.http.user_agent` | User-Agent string |
| `network.http.referral_url` | Referrer URL |
| `network.email.from` | Sender email — **indexed** |
| `network.email.to` | Recipient email — **indexed** |
| `network.email.subject` | Email subject (repeated) |
| `network.tls.version` | TLS version |
| `network.tls.cipher` | TLS cipher |

---

## security_result Fields

| Field | Notes |
|---|---|
| `security_result.action` | ALLOW, ALLOW_WITH_MODIFICATION, BLOCK, QUARANTINE, CHALLENGE, FAIL, UNKNOWN_ACTION |
| `security_result.threat_verdict` | MALICIOUS, SUSPICIOUS, UNDETECTED, THREAT_VERDICT_UNSPECIFIED |
| `security_result.severity` | CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, ERROR, NONE, UNKNOWN_SEVERITY |
| `security_result.category` | See SecurityCategory enum below |
| `security_result.description` | Human-readable result description |
| `security_result.summary` | Brief summary |
| `security_result.rule_name` | Detection rule name |
| `security_result.rule_id` | Vendor rule ID |
| `security_result.threat_name` | Threat classification name |
| `security_result.confidence` | HIGH_CONFIDENCE, MEDIUM_CONFIDENCE, LOW_CONFIDENCE |

### SecurityResult.SecurityCategory values (common)

`SOFTWARE_MALICIOUS` · `SOFTWARE_SUSPICIOUS` · `SOFTWARE_PUA` ·
`NETWORK_MALICIOUS` · `NETWORK_SUSPICIOUS` · `NETWORK_COMMAND_AND_CONTROL` · `NETWORK_DENIAL_OF_SERVICE` · `NETWORK_RECON` ·
`EXPLOIT` · `DATA_EXFILTRATION` · `DATA_DESTRUCTION` · `DATA_AT_REST` ·
`ACL_VIOLATION` · `AUTH_VIOLATION` · `POLICY_VIOLATION` ·
`MAIL_PHISHING` · `MAIL_SPAM` · `MAIL_SPOOFING` · `PHISHING` · `SOCIAL_ENGINEERING` ·
`TOR_EXIT_NODE`

---

## metadata.event_type — Complete Enum

**Enumerated field — do not use regex. List values explicitly with OR.**

### User / Identity
| Value | Description |
|---|---|
| `USER_LOGIN` | User login |
| `USER_LOGOUT` | User logout |
| `USER_CREATION` | User account created |
| `USER_DELETION` | User account deleted |
| `USER_CHANGE_PASSWORD` | Password changed |
| `USER_CHANGE_PERMISSIONS` | Permissions changed |
| `USER_RESOURCE_ACCESS` | User accessed a resource |
| `USER_RESOURCE_CREATION` | User created a resource |
| `USER_RESOURCE_DELETION` | User deleted a resource |
| `USER_RESOURCE_UPDATE_CONTENT` | User updated resource content |
| `USER_RESOURCE_UPDATE_PERMISSIONS` | User updated resource permissions |
| `USER_BADGE_IN` | Physical badge-in |
| `USER_COMMUNICATION` | Communication initiated (video, etc.) |
| `USER_UNCATEGORIZED` | Uncategorized user event |

### Group
| Value | Description |
|---|---|
| `GROUP_CREATION` | Group created |
| `GROUP_DELETION` | Group deleted |
| `GROUP_MODIFICATION` | Group modified (members added/removed) |
| `GROUP_UNCATEGORIZED` | Uncategorized group event |

### File
| Value | Description |
|---|---|
| `FILE_CREATION` | File created |
| `FILE_DELETION` | File deleted |
| `FILE_MODIFICATION` | File modified |
| `FILE_READ` | File read |
| `FILE_COPY` | File copied |
| `FILE_OPEN` | File opened |
| `FILE_MOVE` | File moved or renamed |
| `FILE_SYNC` | File synced (Drive, Dropbox, etc.) |
| `FILE_UNCATEGORIZED` | Uncategorized file event |

### Process
| Value | Description |
|---|---|
| `PROCESS_LAUNCH` | Process launched |
| `PROCESS_TERMINATION` | Process terminated |
| `PROCESS_INJECTION` | Process injected into another |
| `PROCESS_OPEN` | Process opened |
| `PROCESS_PRIVILEGE_ESCALATION` | Privilege escalation |
| `PROCESS_MODULE_LOAD` | Module/DLL loaded |
| `PROCESS_UNCATEGORIZED` | Uncategorized process event |

### Network
| Value | Description |
|---|---|
| `NETWORK_CONNECTION` | Network connection (firewall, etc.) |
| `NETWORK_FLOW` | Aggregated flow stats (NetFlow) |
| `NETWORK_DNS` | DNS payload |
| `NETWORK_DHCP` | DHCP payload |
| `NETWORK_HTTP` | HTTP telemetry |
| `NETWORK_FTP` | FTP telemetry |
| `NETWORK_SMTP` | SMTP telemetry |
| `NETWORK_UNCATEGORIZED` | Uncategorized network event |

### Registry
| Value | Description |
|---|---|
| `REGISTRY_CREATION` | Registry key/value created |
| `REGISTRY_MODIFICATION` | Registry key/value modified |
| `REGISTRY_DELETION` | Registry key/value deleted |
| `REGISTRY_UNCATEGORIZED` | Uncategorized registry event |

### Scheduled Tasks / Services / Settings
| Value | Description |
|---|---|
| `SCHEDULED_TASK_CREATION` | Scheduled task created |
| `SCHEDULED_TASK_DELETION` | Scheduled task deleted |
| `SCHEDULED_TASK_ENABLE` / `DISABLE` / `MODIFICATION` | Task state changed |
| `SERVICE_CREATION` | Service created |
| `SERVICE_DELETION` | Service deleted |
| `SERVICE_START` / `SERVICE_STOP` / `SERVICE_MODIFICATION` | Service state |
| `SETTING_CREATION` / `SETTING_MODIFICATION` / `SETTING_DELETION` | Setting changed |

### Resource (Cloud / Generic)
| Value | Description |
|---|---|
| `RESOURCE_CREATION` | Resource created |
| `RESOURCE_DELETION` | Resource deleted |
| `RESOURCE_READ` | Resource read |
| `RESOURCE_WRITTEN` | Resource written |
| `RESOURCE_PERMISSIONS_CHANGE` | Resource permissions changed |

### Status / Scan / Email / Other
| Value | Description |
|---|---|
| `STATUS_HEARTBEAT` | Agent heartbeat |
| `STATUS_STARTUP` / `STATUS_SHUTDOWN` | Agent start/stop |
| `STATUS_UPDATE` | Software/fingerprint update |
| `STATUS_UNCATEGORIZED` | Uncategorized status |
| `SCAN_FILE` / `SCAN_HOST` / `SCAN_NETWORK` / `SCAN_PROCESS` | Scan events |
| `SCAN_VULN_HOST` / `SCAN_VULN_NETWORK` | Vulnerability scan |
| `EMAIL_TRANSACTION` | Email transaction |
| `EMAIL_UNCATEGORIZED` | Uncategorized email |
| `MUTEX_CREATION` | Mutex created |
| `GENERIC_EVENT` | OS events not matching other types |

---

## High-Performance Filter Fields

Use these as primary filters for fastest query execution. Non-listed `metadata.*` fields are generally not indexed.

**Principal:** `principal.hostname` · `principal.ip` · `principal.mac` · `principal.user.userid` · `principal.user.email_addresses` · `principal.user.windows_sid` · `principal.user.product_object_id` · `principal.file.md5/sha1/sha256` · `principal.process.file.md5/sha1/sha256` · `principal.process.parent_process.file.md5/sha1/sha256` · `principal.asset.hostname` · `principal.asset.ip` · `principal.asset.mac`

**Target:** `target.hostname` · `target.ip` · `target.user.userid` · `target.user.email_addresses` · `target.user.windows_sid` · `target.user.product_object_id` · `target.file.md5/sha1/sha256` · `target.process.file.md5/sha1/sha256` · `target.asset.hostname`

**Source:** `src.hostname` · `src.ip` · `src.user.userid`

**Other:** `network.dns.questions.name` · `network.email.from` · `network.email.to` · `intermediary.hostname` · `intermediary.ip` · `observer.hostname` · `observer.ip` · `metadata.log_type`

---

## Excluded from Filters

Cannot be used as search filters (degrades performance):
- `metadata.id`
- `metadata.product_log_id`
- `*.timestamp` (bare — always use `.seconds` sub-field)
