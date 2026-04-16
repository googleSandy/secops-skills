# SecOps SIEM Search: Best Practices & Syntax Reference

## Section Order

### Stats Query
```
[filter conditions]              ← always first, no section header
[$var = field.name]              ← variable assignments inline with filters
match:
    $var1, $var2                 ← comma-separated group-by keys
outcome:
    $result = function(field)    ← aggregate computations
order:
    $result desc                 ← asc or desc (defaults to asc)
limit:
    20                           ← optional; max 10,000 rows
```

### Join Query
```
events:
    $joinkey = $e1.field         ← assign join key from event 1
    $e1.field = "filter"         ← filter conditions on event 1
    $joinkey = $e2.field         ← same join key from event 2 (enforces equality)
    $e2.field = "filter"         ← filter conditions on event 2
match:
    $joinkey over 30m            ← correlation window (max 48h)
outcome:                         ← optional aggregations
    $count = count_distinct($e2.target.file.full_path)
condition:
    $e1 and $e2                  ← presence requirement
```

Join limits: max 2 UDM events per query; max window 48h.
Join types: Event-Event, Event-ECG (entity graph), Datatable-Event.

## Match Section: Time Granularity

Group results by time bucket alongside other variables:

```
match:
    $hostname, target.ip by 2h       ← every 2 hours
    $hostname over every day          ← every day
    $hostname by minute               ← every minute
    $hostname over every 1w           ← every week
```

Supported granularities: `minute`/`m` · `hour`/`h` · `day`/`d` · `week`/`w` · `month`/`mo`

Both `by` and `over every` are functionally equivalent.

## Performance Rules

1. **Narrow the time range** — max 90 days per query; smallest range = fastest results
2. **Anchor on high-performance fields first** — see `udm-fields.md` for the full list
3. **Prefer exact match over regex** — regex is evaluated per-event; string equality uses the index
4. **Limit regex conditions** — multiple regex in one query compounds compute cost
5. **Use reference lists for large value sets** — `%LIST_NAME.column` is faster than long `OR` chains
6. **Raw log search is always slower** — always combine with at least `metadata.log_type` filter
7. **Statistical queries are delayed** — available 2 hours after ingestion; don't use for real-time

## Timestamp Handling

Timestamp fields require **Unix epoch seconds** — ISO 8601 strings are not valid filter values:

```
metadata.ingested_timestamp.seconds = 1660784400    ✓ valid
metadata.ingested_timestamp = "2022-08-18T01:00:00Z"   ✗ invalid
```

To group by date in the `match:` section, extract a date string first:

```
$date = timestamp.get_timestamp(metadata.event_timestamp.seconds, "%F")
// or with timezone:
$date = timestamp.get_date(metadata.event_timestamp.seconds, "America/Los_Angeles")

match:
    $hostname, $date
```

Use `earliest()` / `latest()` in `outcome:` to capture first/last timestamp in a group:

```
outcome:
    $first_seen = earliest(metadata.event_timestamp)
    $last_seen = latest(metadata.event_timestamp)
```

## Repeated Fields

Some UDM fields hold multiple values (e.g. `principal.ip`, `target.file.md5`). They are evaluated with implicit `any`:

- `principal.ip != "1.2.3.4"` matches events that have **any** IP other than `1.2.3.4` — including events that also have `1.2.3.4`
- Be precise with `!=` on repeated fields; results may be broader than expected

## Operators & Syntax Rules

| Rule | Detail |
|---|---|
| Implicit AND | Newline-separated conditions are implicitly AND-ed |
| Explicit operators | `AND`, `OR`, `NOT` are valid; use `()` for precedence (max 169 logical operators) |
| Comparison | `=` `!=` `>` `>=` `<` `<=` |
| Regex | `/pattern/ nocase` — `nocase` after closing slash; only valid on non-enumerated fields |
| String literal | `= "value"` — `nocase` is NOT valid on string literals |
| Enumerated fields | `metadata.event_type`, `network.ip_protocol` — no regex; use explicit OR list |
| Map/label access | `field["key"]` for `labels`, `ingestion_labels`, `resource.attribute.labels` |
| Reference lists | `%LIST_NAME.column_name` |
| Variable assignment | `$var = field.name` — inline with filters; `$` prefix required |
| Raw log search limit | 150 characters max in the `raw =` expression |
