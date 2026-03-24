# Detection Engineering: Troubleshooting

Sources:
- https://docs.cloud.google.com/chronicle/docs/detection/rule-errors
- https://docs.cloud.google.com/chronicle/docs/detection/troubleshoot-rule-errors

---

## Compilation Errors

Shown immediately on save or test. Rule cannot be saved until fixed.

Error appears as a red underline at the problem location. For complex errors
spanning multiple locations, no position is shown.

**Common compilation errors and fixes:**

| Error | Cause | Fix |
|---|---|---|
| Both sides of comparison are literals | `"value1" = "value2"` | One side must be a field or variable |
| Variable used without declaration | `$user` used but never assigned in `events:` | Declare with `$user = $e.field.name` |
| Enumerated field with regex | `metadata.event_type = /USER_.*/` | Use exact string with OR: `= "USER_LOGIN" or = "USER_LOGOUT"` |
| `or` in condition with multiple event vars | `$e1 or $e2` | Use `and` for multiple event variables |
| Placeholder used in match but not in events | `match: $user` with no assignment | Add `$user = $e.field` in events section |

---

## Runtime Errors

Occur during test, retrohunt, or live rule execution. Not shown at compile time.

**To check:** Click **Run Test** in the editor. If a runtime error occurs, follow the error link.
For live/retrohunt errors, follow the error link on the Detections page.

### Full Runtime Error Reference

| Error message | Cause | Resolution |
|---|---|---|
| `query took too long to execute` | Rule too complex or data volume too high | Add `metadata.event_type` / `metadata.log_type` filter; reduce match window |
| `Not enough memory for aggregation` | `aggregate_memory_limit` exceeded | Reduce number of keys in `match:` section |
| `Spilled bytes exceed limit` | Too many events processed | Add specific filters (`metadata.log_type`, `metadata.event_type`) |
| `Your query resource usage is exceeding its allocation` | Resource manager cancelled query | Add filters; simplify aggregations |
| `Request was throttled, please try again later` | Complex joins or large aggregations; or system under load | Add more specific event filters; retry after delay |
| `Too many OR and AND operations` | Deeply nested logic, exceeds stack limits | Simplify conditions; break into multiple rules |
| `Query is too long` | Too much stack space required | Split into multiple simpler rules |
| `Accessing a new field that did not exist for this time range` | Field added to schema after the rule's time range | Adjust time range to start after field was present; handle null case |
| `Invalid subnet CIDR` | Malformed CIDR range in `net.ip_in_range_cidr()` | Verify CIDR format (e.g. `10.0.0.0/8`) |
| `Invalid IP address` | Malformed IP in filter or function | Ensure field contains valid IP format |
| `Map access for reading label does not support duplicate map keys` | Duplicate keys in `additional.fields` or similar map | Investigate data source; adapt rule logic |
| `Invalid regular expression` | Malformed regex in `re.regex()` or literal | Fix regex syntax; test with RE2 tester |
| `Invalid re.replace()` | Mismatch between parenthesized groups and replacement references | Ensure replacement references match capture groups |
| `Integer overflow in sum()` | Sum exceeds max integer | Cast to float: `sum(0.0 + $e.field)` |
| `Cannot complete arithmetic between unsigned and signed integer` | Mixed signed/unsigned arithmetic | Use `cast.as_int()` or `cast.as_uint()` to match types |
| `Error reading files` / `Error reading database` | Transient backend issue | Retry; contact support if persistent |
| `Internal error` / `Unknown error` | System-level error without specific message | Retry; contact Google SecOps support |

**Note:** Runtime errors sometimes resolve on their own if caused by a backend bug that was subsequently fixed.

---

## Rule Fires But No/Unexpected Detections

**Checklist:**
1. Is the rule enabled as **Live Rule**? (check toggle in Rules Dashboard)
2. Is **alerting** enabled for the rule?
3. Check **detection delays** — multi-event rules wait for full match window
4. Verify data is actually ingested: use raw log search for the same time range
5. Check field names: use the UDM field lookup or autocomplete to verify
6. Run **retrohunt** over a known time range with known events to validate logic
7. Check for **zero-value joins**: add `$field != ""` to prevent empty-string matches
8. Check if `options: allow_zero_values` is needed (or unintentionally set)

---

## Data Verification Before Writing Rules

Before writing a detection, verify the data exists and is normalized correctly:

```yara
// Search for the log type first
metadata.log_type = "WINEVTLOG"
metadata.product_event_type = "4625"    // failed login

// Check what fields are actually populated
metadata.log_type = "WINEVTLOG"
$e.metadata.event_type = "USER_LOGIN"
limit: 10
```

See also: https://docs.cloud.google.com/chronicle/docs/detection/verify-data-ingestion

---

## Performance Errors: Prevention

| Rule pattern | Risk | Prevention |
|---|---|---|
| No event type filter | Scans all events | Always add `metadata.event_type` or `metadata.log_type` |
| Many OR conditions | Stack overflow | Use reference lists instead |
| Large `array()` aggregations | Memory limit | Use `array_distinct()` and limit outcome variables |
| Very wide match windows | Slow correlation | Use smallest window that captures the threat |
| Multiple regex conditions | High compute | Prefer exact matches; use regex only when needed |
| Large data table joins | Memory pressure | Add pre-filters to reduce events before join |
