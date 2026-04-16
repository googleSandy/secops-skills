# Detection Engineering: Live Documentation Sources

Fetch live docs first. Fall back to static reference files if pages don't load.

---

## Official Documentation

| Topic | URL | Static fallback |
|---|---|---|
| Manage rules (create, test, deploy) | https://docs.cloud.google.com/chronicle/docs/detection/manage-all-rules | `workflow.md` |
| Run rule on live data | https://docs.cloud.google.com/chronicle/docs/detection/run-rule-live-data | `workflow.md` |
| Run rule on historical data (retrohunt) | https://docs.cloud.google.com/chronicle/docs/detection/run-rule-historical-data | `workflow.md` |
| Detection delays | https://docs.cloud.google.com/chronicle/docs/detection/detection-delays | `delays-and-performance.md` |
| Optimize detection performance (MTTD) | https://docs.cloud.google.com/chronicle/docs/detection/optimize-detection-and-reporting-performance | `delays-and-performance.md` |
| Context-aware analytics (entity graph in rules) | https://docs.cloud.google.com/chronicle/docs/detection/context-aware-analytics | `context-and-risk.md` |
| Entity risk score in rules | https://docs.cloud.google.com/chronicle/docs/detection/yara-l-entity-risk-score | `context-and-risk.md` |
| Risk-based alerting (ENTITY_RISK_CHANGE) | https://docs.cloud.google.com/chronicle/docs/detection/risk-based-alerting | `context-and-risk.md` |
| Rule errors (compilation + runtime) | https://docs.cloud.google.com/chronicle/docs/detection/rule-errors | `troubleshooting.md` |
| Troubleshoot runtime errors | https://docs.cloud.google.com/chronicle/docs/detection/troubleshoot-rule-errors | `troubleshooting.md` |
| Composite detections overview | https://docs.cloud.google.com/chronicle/docs/detection/composite-detections | `composite-detections.md` |
| Composite detection rule syntax | https://docs.cloud.google.com/chronicle/docs/yara-l/composite-detection-rules | `composite-detections.md` |
| Verify data ingestion | https://docs.cloud.google.com/chronicle/docs/detection/verify-data-ingestion | `troubleshooting.md` |
| MITRE ATT&CK matrix dashboard | https://docs.cloud.google.com/chronicle/docs/detection/mitre-dashboard | `docs.md` (see MITRE section below) |
| Rule quotas and capacity | https://docs.cloud.google.com/chronicle/docs/detection/rules-capacity | `workflow.md` |
| Set run frequency | https://docs.cloud.google.com/chronicle/docs/detection/set-customized-schedule | `delays-and-performance.md` |

## Sample Detection Rules

| Resource | URL | Notes |
|---|---|---|
| **Google Chronicle detection rules (GitHub)** | https://github.com/chronicle/detection-rules | Official sample YARA-L rules organized by category — reference for detection patterns |
| YARA-L examples (official docs) | https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples | — |

## Community Blog Posts (Detection Engineering)

| Topic | URL |
|---|---|
| Building a rule to monitor risky behavior | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-building-a-rule-to-monitor-for-risky-behavior-4003 |
| Building rules with threat intel (Part 1) | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-building-rules-with-your-own-threat-intel-part-1-4039 |
| Safe Browsing integration in rules | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-safe-browsing-integration-4037 |
| Excluding entities using data tables | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-excluding-entities-from-rules-using-data-tables-6138 |
| Intro to extending entity graph with data tables | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-an-introduction-to-extending-the-entity-graph-with-data-tables-5983 |
| Appending data tables to entity graph | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-appending-data-tables-to-the-entity-graph-6199 |
| Build rules while appending data tables to ECG | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-build-rules-while-appending-data-tables-to-the-entity-graph-6235 |
| Joins in detection (Love Will Tear Us Apart) | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-love-will-tear-us-apart-but-joins-keep-us-together-6833 |
| Watching the Detectives: connect the dots | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-watching-the-detectives-connect-the-dots-6942 |
| MAD World: robust metric with multi-stage | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-mad-world-the-multi-stage-search-for-a-robust-metric-6595 |
| Policy of Truth: detecting outliers with Z-scores | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-policy-of-truth-detecting-outliers-with-robust-z-scores-6596 |
| Leveraging Okta curated detections | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-leveraging-okta-curated-detections-to-detect-shinyhunters-related-activity-6693 |

---

## MITRE ATT&CK Integration

**Dashboard:** Detection > MITRE ATT&CK Matrix (requires ATT&CK matrix access)

SecOps supports **ATT&CK version 17**. The matrix visualizes your detection coverage
across tactics and techniques as a heat map.

### Tactic Overview

| Tactic | Goal |
|---|---|
| Initial Access | Gain entry to the environment |
| Execution | Run malicious code |
| Persistence | Maintain foothold |
| Privilege Escalation | Gain higher-level permissions |
| Defense Evasion | Avoid detection |
| Credential Access | Steal credentials |
| Discovery | Map the environment |
| Lateral Movement | Move through the environment |
| Collection | Gather data |
| Command and Control | Contact controlled infrastructure |
| Exfiltration | Steal data |
| Impact | Disrupt or destroy systems/data |
| Reconnaissance | Pre-attack information gathering (PRE platform) |
| Resource Development | Pre-attack resource establishment (PRE platform) |

### Using the MITRE Matrix for Detection Engineering

**Identify gaps:** Browse the matrix to find techniques with no detection coverage.
Blank/low-coverage cells indicate areas to prioritize new rule development.

**Respond to threat advisories:** When a new advisory identifies ATT&CK techniques,
filter the matrix to see if you have coverage for those specific techniques.

**Tune existing detections:** Techniques with many detections may be over-detected.
Review those rules for false-positive reduction opportunities.

### Tag Rules with MITRE ATT&CK

Add MITRE technique IDs to rule `meta:` sections to contribute to matrix coverage:

```yara
meta:
  author             = "Security Team"
  description        = "Detects credential dumping via LSASS"
  severity           = "CRITICAL"
  mitre_attack_tactic     = "Credential Access"
  mitre_attack_technique  = "OS Credential Dumping"
  mitre_attack_technique_id = "T1003"
  mitre_attack_subtechnique = "LSASS Memory"
  mitre_attack_subtechnique_id = "T1003.001"
```

Rules with these `meta:` fields are mapped to the corresponding technique cell
in the MITRE ATT&CK dashboard, contributing to your organization's measured coverage.

**Export:** The MITRE matrix can be exported for offline analysis and reporting.
