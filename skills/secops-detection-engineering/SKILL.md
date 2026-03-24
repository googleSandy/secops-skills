---
name: secops-detection-engineering
description: |
  Use when creating, testing, deploying, or managing Google SecOps detection rules —
  the detection engineering workflow, retrohunts, rule quotas, detection delays, context-aware
  analytics (entity graph in rules), risk scoring, error troubleshooting, performance
  optimization, or composite detections. Complements secops-yara-l (YARA-L query syntax)
  with the detection engineering workflow. Triggers: "create a detection rule", "deploy rule",
  "retrohunt", "rule not firing", "detection delay", "entity graph in rule", "risk score rule",
  "composite detection", "rule error", "tune a rule".
compatibility: Requires access to a Google Security Operations (SecOps) SIEM instance with Detection Engine enabled.
---

# SecOps Detection Engineering

## Detection Engineering Workflow

```
Write rule (YARA-L) → Test (Run Test) → Retrohunt (historical) → Deploy (Live Rule)
                              ↓                    ↓
                         Non-persistent      Generates real
                         No alerts           detections & alerts
```

**See `references/workflow.md`** for full lifecycle, rule management, and quotas.

---

## Testing Approaches

| Method | What it does | Generates alerts? | Persists? |
|---|---|---|---|
| **Run Test** | Runs rule on a specified time range in editor | No | No |
| **Retrohunt** | Applies rule to historical data | Yes (if alerting enabled) | Yes |
| **Live Rule** | Runs continuously on incoming data | Yes | Yes |

**Key testing notes:**
- `Run Test` applies `suppression_window` — suppression is NOT applied during test
- Successive test runs may produce different results (parallel execution, timing differences)
- Test results won't appear in the Rules Dashboard
- For retrohunt on multi-event rules: time range must be ≥ match window size

---

## Run Frequency vs Detection Latency

Choose frequency based on rule type and match window:

| Rule type | Recommended frequency |
|---|---|
| Single-event rules | **Near real-time** |
| Multi-event rules, window < 60m | **10 minutes** |
| Multi-event rules, window ≥ 60m | **1 hour** or **24 hours** |

Higher frequency = lower latency but more compute. Non-existence rules (`not $e2`)
add ~1 hour delay regardless of frequency.

---

## Entity Graph in Rules (Context-Aware)

Join UDM events with entity context data using explicit source prefixes:

```yara
events:
  // UDM event (default source, or explicit udm prefix)
  $e1.principal.hostname = $host
  // or: $e1.udm.principal.hostname = $host

  // Entity context (explicit graph prefix)
  $e2.graph.entity.hostname = $host
  $e2.graph.entity.resource.attribute.roles.type = "ADMINISTRATOR"

match:
  $host over 2m

condition:
  $e1 and $e2
```

**Rules:** Multi-event rules must include at least one UDM event — cannot join entity-only.
**Source prefixes:** `udm` (default), `graph` (entity context graph)

→ Full examples and qualifier reference: `references/context-and-risk.md`

---

## Risk Score Rules

```yara
rule EntityRiskScore {
  meta:
    severity = "HIGH"
  events:
    $e1.principal.hostname != ""
    $e1.principal.hostname = $hostname

    $e2.graph.entity.hostname = $hostname
    $e2.graph.risk_score.risk_window_size.seconds = 86400   // 24h window
    $e2.graph.risk_score.risk_score >= 100

  match:
    $hostname over 5m

  condition:
    $e1 and $e2
}
```

Use `outcome: $risk_score = <value>` to assign a risk score to a detection.
Use `outcome: $risk_entity_to_score = $e.principal.ip` to specify which entity gets scored.

---

## Composite Detections

Composite rules use **detections from other rules** as input, not raw UDM events.
Reference fields use `$d.detection.*` instead of `$e.udm.*`.

```yara
rule composite_admin_detection {
  events:
    $rule_name     = $d.detection.detection.rule_name
    $principal     = $d.detection.detection.outcomes["principal_users"]
    $principal     = /admin|root/ nocase
  match:
    $principal over 1h
  outcome:
    $risk_score     = 75
    $upstream_rules = array_distinct($rule_name)
  condition:
    $d
}
```

→ Use cases, strategy, and limitations: `references/composite-detections.md`

---

## Common Error Patterns

| Error | Quick fix |
|---|---|
| `query took too long to execute` | Add `metadata.event_type` or `metadata.log_type` filter; reduce match window |
| `Not enough memory for aggregation` | Reduce keys in `match:` section |
| `Too many OR and AND operations` | Split logic into multiple simpler rules |
| `Cannot complete arithmetic between unsigned and signed integer` | Use `cast.as_int()` or `cast.as_uint()` |
| `Integer overflow in sum()` | Use `sum(0.0 + $e.field)` to cast to float |
| Compilation error on save | Fix highlighted line; both sides of comparison can't be literals |
| Rule fires but no detections | Check alerting status, Live Rule toggle, and detection delays |

→ Full error table: `references/troubleshooting.md`

---

## Gotchas

Environment-specific facts that defy reasonable assumptions:

- **Saving a rule does NOT enable it** — new rules are always saved in disabled state. The Live Rule toggle must be manually enabled in the Rules Dashboard.
- **Retrohunt with alerting disabled generates no alerts** — if you want alerts from a retrohunt, enable alerting on the rule first, then re-run the retrohunt.
- **`suppression_window` is not applied during Run Test** — suppression only takes effect after a detection is written by a live rule. Test results always show all detections.
- **Non-existence conditions add ~1 hour delay** — rules with `not $e2` in `condition:` wait for late-arriving data, adding ~1h to expected detection time.
- **Composite rules inherit all upstream delays** — a chain of rules with hourly run frequency accumulates hours of cumulative latency.
- **Multi-event rules for retrohunt: time range must be ≥ match window** — a retrohunt over 5 minutes for a rule with `over 1h` will fail.
- **`setup:` section must appear before `events:`** — placing `graph_exclude` or `graph_override` after `events:` is a compile error.
- **Reference lists are deprecated (June 2026)** — use data tables (`%table.column`) in new rules instead of `%reference_list`.

## Reference Files

- Read `references/workflow.md` for the full create/test/retrohunt/deploy lifecycle, rule management, or quota details
- Read `references/delays-and-performance.md` when diagnosing why detections are slow or to optimize MTTD
- Read `references/context-and-risk.md` when using entity graph in rules, risk scores, Safe Browsing, or threat intel IOC joins
- Read `references/troubleshooting.md` when a rule has a compilation or runtime error — includes the full error table with fixes
- Read `references/composite-detections.md` when building rules that chain upstream detections
- Read `references/docs.md` for live documentation URLs and the parser list refresh workflow
