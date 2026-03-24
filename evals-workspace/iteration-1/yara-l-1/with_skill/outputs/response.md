# YARA-L 2.0 Detection Rule: Multiple Failed Logins

## Rule: MultipleFailedLogins

```yara
rule MultipleFailedLogins {
  meta:
    author        = "Security Team"
    description   = "Detects 5 or more failed login attempts for the same user within 10 minutes"
    severity      = "HIGH"
    detection_type = "Authentication Abuse"

  events:
    $e.metadata.event_type     = "USER_LOGIN"
    $e.security_result.action  = "FAIL"
    $user = $e.target.user.userid

  match:
    $user over 10m

  outcome:
    $count = count($e.metadata.id)

  condition:
    #e > 4
}
```

## Rule Explanation

**meta:** Required metadata section with:
- `author`: Security team responsible for the rule
- `description`: Clear statement that rule detects 5+ failed logins for same user within 10-minute window
- `severity`: HIGH severity due to brute-force attack implications
- `detection_type`: Classification for organization purposes

**events:** Defines event matching criteria:
- `$e.metadata.event_type = "USER_LOGIN"` - Filters for login events (exact string, no regex)
- `$e.security_result.action = "FAIL"` - Filters for failed login attempts (exact string, no regex)
- `$user = $e.target.user.userid` - Placeholder variable storing the user ID for grouping

**match:** Aggregation operator:
- `$user over 10m` - Groups all events by user ID, sliding window of 10 minutes

**outcome:** Result calculation:
- `$count = count($e.metadata.id)` - Counts the number of distinct event IDs (events matching criteria)

**condition:** Trigger logic:
- `#e > 4` - Fires when count of events exceeds 4 (which equals 5 or more failed login attempts)
  - `#e` = count of matching events
  - `> 4` = threshold for 5+ attempts

## Detection Behavior

- **Trigger**: When a single user has 5+ failed login attempts within any 10-minute sliding window
- **False Positives**: May trigger on legitimate failed password entries; tune severity based on organization's acceptable failure rate
- **Use Cases**: Brute-force attack detection, account compromise investigation, authentication anomaly alerting
