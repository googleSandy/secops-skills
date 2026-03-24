# YARA-L Detection Rule: Multiple Failed Login Attempts

## Rule: Multiple Failed Logins in Short Timeframe

```yara-l
rule multiple_failed_logins_10min {
  meta:
    author = "Security Operations"
    description = "Detects when the same user has 5 or more failed login attempts within 10 minutes"
    severity = "MEDIUM"
    created = "2026-03-20"

  events:
    $login_failed = metadata.event_type == "USER_LOGIN" and
                    metadata.log_source == "AUTH" and
                    metadata.fail_reason != null

  match:
    $login_failed over 10m with max_span = 10m where
    $login_failed.user_name == $login_failed.user_name

  condition:
    #$login_failed >= 5
}
```

## Explanation

### Key Components:

1. **Event Selection** (`events` clause):
   - Filters for login events (`metadata.event_type == "USER_LOGIN"`)
   - Targets authentication logs (`metadata.log_source == "AUTH"`)
   - Identifies failed attempts (`metadata.fail_reason != null`)

2. **Time Window** (`over 10m`):
   - Analyzes events within a 10-minute sliding window
   - `max_span = 10m` ensures all events in the match occur within 10 minutes

3. **Grouping** (`where $login_failed.user_name == $login_failed.user_name`):
   - Groups events by the same user
   - Ensures all 5 failed attempts are from the same user account

4. **Threshold** (`#$login_failed >= 5`):
   - Triggers alert when 5 or more failed login events are detected
   - The `#` operator counts matching events

## Alternative Version (If using different field names)

If your data source uses different field names, adapt accordingly:

```yara-l
rule multiple_failed_logins_10min_alt {
  meta:
    author = "Security Operations"
    description = "Detects when the same user has 5 or more failed login attempts within 10 minutes"
    severity = "MEDIUM"

  events:
    $login_failed = event_type == "authentication" and
                    authentication_status == "failed"

  match:
    $login_failed over 10m with max_span = 10m where
    $login_failed.username == $login_failed.username

  condition:
    #$login_failed >= 5
}
```

## Expected Behavior

- **Triggers when**: A single user account experiences 5+ failed login attempts within any 10-minute window
- **Examples that trigger**:
  - User attempts to login 5 times in 5 minutes (all fail)
  - User attempts to login 7 times across 9 minutes (all fail)

- **Examples that do NOT trigger**:
  - Same user with 4 failed attempts + 1 success within 10 minutes
  - 5 failed attempts spread across 15 minutes
  - 5 failed attempts from different users within same 10-minute window

## Integration Notes

- This rule is designed for Chronicle (Google Cloud's SIEM)
- Adjust field names (`user_name`, `metadata.log_source`, etc.) to match your specific log schema
- Can be enhanced with additional filters (e.g., exclude service accounts, specific IPs)
- Consider alerting on this rule with medium or high priority depending on your environment
