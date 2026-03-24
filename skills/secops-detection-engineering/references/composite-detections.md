# Detection Engineering: Composite Detections

Source: https://docs.cloud.google.com/chronicle/docs/detection/composite-detections

---

## What are Composite Detections?

Composite rules use **detections from other rules as input** — not raw UDM events.
They enable multi-stage attack detection by correlating outputs of existing rules.

**Input:** Detections from upstream rules (accessed via `$d.detection.*`)
**Output:** New detections (which can themselves feed further composite rules)

---

## When to Use

- Correlate outcomes of 2+ rules (e.g., Malware Downloaded + subsequent C2 Beaconing from same host)
- Reduce alert fatigue: only fire when a noisy low-confidence detection occurs N times or with other signals
- Build alerts for multi-stage attacks where each stage has its own rule
- Enrich alerts with related event data from other detections

## When NOT to Use

- When a single-rule or multi-event UDM rule can do the job — composite rules inherit upstream delays
- When you need real-time detection (composite rules depend on upstream rule runs completing first)

---

## Design Strategy

1. **Evaluate existing rules** — identify noisy rules that generate false positives
2. **Identify multi-stage scenarios** — map out attack stages already covered by individual rules
3. **Define the composite trigger** — what combination of detections constitutes a high-confidence alert?
4. **Build bottom-up** — ensure upstream rules are stable before adding composite logic on top

---

## Rule Structure

Composite rules reference upstream detections via `$d.detection.*` fields:

```yara
rule composite_admin_detection {
  meta:
    description = "Any detection where the actor is an admin user"
    severity    = "MEDIUM"

  events:
    $rule_name      = $d.detection.detection.rule_name
    $principal_user = $d.detection.detection.outcomes["principal_users"]
    $principal_user = /admin|root/ nocase

  match:
    $principal_user over 1h

  outcome:
    $risk_score     = 75
    $upstream_rules = array_distinct($rule_name)

  condition:
    $d
}
```

**Key field paths for composite rules:**

| Field path | Content |
|---|---|
| `$d.detection.detection.rule_name` | Name of the upstream rule |
| `$d.detection.detection.rule_id` | ID of the upstream rule |
| `$d.detection.detection.outcomes["key"]` | Outcome variable from upstream rule |
| `$d.detection.detection.match_variables["key"]` | Match variable from upstream rule |

---

## Sequential Composite Detection

Detect a sequence of events: upstream rule A fires, then upstream rule B fires for the same entity.

```yara
rule SequentialAttack {
  meta:
    description = "Recon followed by lateral movement on same host within 2 hours"
    severity    = "CRITICAL"

  events:
    $recon.detection.detection.rule_name = "ReconDetection"
    $recon.detection.detection.outcomes["target_host"] = $host

    $lateral.detection.detection.rule_name = "LateralMovement"
    $lateral.detection.detection.outcomes["target_host"] = $host

  match:
    $host over 2h after $recon    // sliding window anchored to recon detection

  condition:
    $recon and $lateral
}
```

---

## Threshold/Aggregation Composite

Fire when the same entity generates a high volume of alerts (risk aggregation):

```yara
rule HighRiskUserAggregate {
  meta:
    description = "User with >5 detections and total risk score >300 in 24h"
    severity    = "HIGH"

  events:
    $user = $d.detection.detection.outcomes["principal_users"]
    $risk = $d.detection.detection.outcomes["risk_score"]

  match:
    $user over 24h

  outcome:
    $total_risk    = sum($risk)
    $alert_count   = count($d.detection.detection.rule_name)
    $rules_fired   = array_distinct($d.detection.detection.rule_name)

  condition:
    #d > 5 and $total_risk > 300
}
```

---

## Combine Events and Detections

A composite rule can join both UDM events and upstream detections:

```yara
rule DetectionWithUDMContext {
  meta:
    severity = "HIGH"

  events:
    // Upstream detection
    $d.detection.detection.rule_name = "SuspiciousLogin"
    $host = $d.detection.detection.outcomes["hostname"]

    // UDM event providing additional context
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.hostname = $host
    $e.target.process.command_line = /mimikatz/ nocase

  match:
    $host over 30m after $d

  condition:
    $d and $e
}
```

---

## Limitations

| Limit | Value |
|---|---|
| Maximum composite depth (rule chain) | 10 levels |
| Maximum match window | **14 days** (composite rules only) |
| Daily detection limit per rule | 10,000 |
| Maximum outcome variables per rule | 20 |
| Max values per repeated outcome variable | 25 |

**SOAR case data:** Composite rules cannot filter based on SOAR case status
(e.g., filtering on `status != "CLOSED"` is not supported).

**Latency:** Composite rules inherit the detection delays of all upstream rules.
A chain of 3 rules with hourly frequency each can add 3+ hours of latency.

---

## Cumulative Risk Score Pattern

Aggregate risk scores across all rules firing for the same user in a 24-hour window.
This pattern builds a "risk budget" — many low-confidence detections combine into
a high-confidence composite alert.

```yara
rule composite_cumulative_risk_score_threshold_exceeded_user {
  meta:
    author      = "Google Cloud Security"
    description = "User exceeds cumulative risk score threshold from all rules in 24h"
    severity    = "High"
    type        = "composite"

  events:
    $detect_prod.detection.detection.outcomes["principal_user_userid"] = $user
    $detect_prod.detection.detection.outcomes["principal_user_userid"] != "SYSTEM"
    // Uncomment to exclude specific rule types:
    // $detect_prod.detection.detection.rule_name != /^producer_/
    // $detect_prod.detection.detection.rule_labels["type"] != "composite"

  match:
    $user over 24h

  outcome:
    $risk_score              = 60   // score for this composite detection itself
    $uniq_detection_count    = count_distinct($detect_prod.detection.detection.rule_id)
    $total_detection_count   = count($detect_prod.detection.detection.rule_id)
    $rules_triggered         = array_distinct($detect_prod.detection.detection.rule_name)
    $cumulative_risk_score   = sum($detect_prod.detection.detection.risk_score)
    // Alternate: sum from outcomes map if risk_score stored there
    $key_value_risk_score    = sum(cast.as_float($detect_prod.detection.detection.outcomes["risk_score"]))

  condition:
    $detect_prod and $cumulative_risk_score > 300   // tune threshold per environment
}
```

**Design notes:**
- Set `$risk_score` in upstream producer rules proportional to threat confidence
- Tune `$cumulative_risk_score > 300` based on your baseline alert volume
- Filter out system accounts and self-referential composite rules using commented-out lines
- Use `$key_value_risk_score` if risk_score is stored in outcomes map vs. native field

---

## Optimizing Composite Detections

- Use the most frequent run schedule for upstream rules (reduces cascade latency)
- Keep composite depth shallow — prefer 2–3 levels maximum
- Use outcome variables in upstream rules to pass context cleanly to composite rules
- Test each rule in the chain independently before testing the composite
- Use retrohunt at each level to verify the detection chain works end-to-end
