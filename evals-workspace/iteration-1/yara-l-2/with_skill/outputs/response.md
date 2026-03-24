# YARA-L 2.0 Rule Analysis

## Problem Identified

The compile error is caused by this line:

```
$e.metadata.event_type = /USER_LOGIN|USER_LOGOUT/
```

## Why It Fails

**Enumerated fields (like `metadata.event_type`) CANNOT use regex patterns.**

According to YARA-L 2.0 specifications:
- `metadata.event_type` is an enumerated field
- Enumerated fields do not support regex syntax (the `/pattern/` notation)
- This will cause a compile error

## Solution

Replace the regex with explicit OR conditions using string literals:

```
($e.metadata.event_type = "USER_LOGIN" or $e.metadata.event_type = "USER_LOGOUT")
```

## Corrected Rule Fragment

```
events:
  ($e.metadata.event_type = "USER_LOGIN" or $e.metadata.event_type = "USER_LOGOUT")
  $e.principal.hostname = $host
```

## Why This Works

- String literals work with enumerated fields
- The OR condition allows matching either value
- No regex syntax needed for enumerated field comparisons
