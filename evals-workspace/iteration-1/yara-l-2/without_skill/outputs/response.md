# YARA-L Rule Compilation Error Analysis

## The Problem

The YARA-L rule fragment has a **missing rule structure keyword** error:

```yara-l
events:
  $e.metadata.event_type = /USER_LOGIN|USER_LOGOUT/
  $e.principal.hostname = $host
```

## Root Cause

The `events:` section is incomplete. In YARA-L 2.0, the syntax requires the **`match:` keyword** to specify what constitutes a match for this rule. The current fragment only defines event conditions but never specifies how they should be combined or what triggers a detection.

## The Fix

The rule needs both:
1. **Event conditions** (what you have under `events:`)
2. **Match logic** (missing - this tells the rule when to alert)

Corrected structure:

```yara-l
events:
  $e.metadata.event_type = /USER_LOGIN|USER_LOGOUT/
  $e.principal.hostname = $host

match:
  $e
```

Or, if you need multiple events:

```yara-l
events:
  $e.metadata.event_type = /USER_LOGIN|USER_LOGOUT/
  $e.principal.hostname = $host

match:
  $e
```

## Explanation

- **`events:` section** - Defines the event patterns to search for (variables like `$e`)
- **`match:` section** - Specifies the logic for what constitutes a match (e.g., `$e` means "match any event `$e`")

Without the `match:` section, the compiler doesn't know what conditions should trigger an alert, resulting in a compilation error.

## Additional Note

If you need more complex match logic (e.g., "alert if a specific user logs in and out within 5 minutes"), you would add conditions to the `match:` section:

```yara-l
match:
  $e and $e.metadata.event_type = "USER_LOGIN"
```
