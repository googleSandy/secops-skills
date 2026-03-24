# YARA-L 2.0: Expressions, Operators & Constructs

Source: https://docs.cloud.google.com/chronicle/docs/yara-l/expressions

---

## Operators

| Operator | Meaning |
|---|---|
| `=` | Equal / variable declaration |
| `!=` | Not equal |
| `<` | Less than |
| `<=` | Less than or equal |
| `>` | Greater than |
| `>=` | Greater than or equal |

Both sides can be: event field, variable, literal, or function result.
**Cannot** compare two literals directly (compilation error).

---

## Boolean Expressions

Used in `events:` and `outcome:` sections.

```yara
$e.source.port < 1024
$e.source.hostname = "host1234"
$e1.source.hostname != $e2.target.hostname
$e.metadata.event_type = "USER_LOGIN"
```

**Logical operators:** `and`, `or`, `not`

```yara
$e.metadata.event_type = "USER_LOGIN" and
$e.security_result.action = "FAIL"

not $e.principal.hostname = "benign-host"
```

---

## Nocase Modifier

Append `nocase` to make string or regex comparisons case-insensitive.

```yara
$e.principal.hostname = "http-server" nocase
$e.principal.hostname != "http-server" nocase
$e1.principal.hostname = $e2.target.hostname nocase
$e.target.url = /phishing.*page/ nocase
```

**`nocase` is only valid on string literals and regex — not on string-to-string variable comparisons.**

## Regex Literal Pitfalls

```yara
// ❌ WRONG — /i flag does not exist in YARA-L
$e.target.process.file.full_path = /wscript\.exe/i

// ✓ CORRECT — use nocase keyword after closing slash
$e.target.process.file.full_path = /wscript\.exe/ nocase

// ❌ WRONG — $ inside regex may cause "literal not terminated"
$e.target.process.file.full_path = /wscript\.exe$/

// ✓ CORRECT — omit $ anchor; sufficient without it
$e.target.process.file.full_path = /wscript\.exe/ nocase

// ❌ WRONG — / inside regex closes the literal early → "literal not terminated"
$e.target.file.full_path = /^[d-zD-Z]:\//   // forward slash ≠ Windows backslash

// ✓ CORRECT — Windows path separator is \ (escaped as \\ in regex)
$e.target.file.full_path = /^[d-zD-Z]:\\/  nocase

// ❌ WRONG — missing = operator before regex
$e.target.process.file.names /wscript\.exe/ nocase

// ✓ CORRECT
$e.target.process.file.names = /wscript\.exe/ nocase
```

**Escape reference for regex literals:**

| To match | Write in regex | Example |
|---|---|---|
| Literal `\` (Windows path sep) | `\\` | `/\\Temp\\/` matches `\Temp\` |
| Literal `\\` (UNC prefix) | `\\\\` | `/^\\\\/` matches `\\server` |
| Literal `.` | `\.` | `/wscript\.exe/` |
| Literal `/` | `\/` | `/path\/to\/file/` |
| End of string | avoid `$` | use specific suffix pattern instead |
| Regex ending with `\` | avoid `\\/` at end of literal | `\\/` = tokenized as `\/` (escaped `/`), never closes the literal — use `\\.*` or restructure |

**Never end a regex literal with `\\`:**
```yara
// ❌ WRONG — \\ before closing / is tokenized as \/ (escaped forward slash)
//           The literal is never closed → "literal not terminated"
$e.target.file.full_path = /\\[Tt]emp\\/    // tokenizer reads \/ as escaped /, keeps going
$e.target.file.full_path = /^\\\\.+\\/      // same problem at the end
$e.target.file.full_path = /^[d-zD-Z]:\\/   // same problem

// ✓ CORRECT — remove trailing \\ or extend pattern beyond it
$e.target.file.full_path = /\\[Tt]emp/ nocase                    // just match \Temp
$e.target.file.full_path = /\\\\.*\.(vbs|vbe)/ nocase            // UNC: \\ + chars + ext
$e.target.file.full_path = /[d-zD-Z]:\\.*\.(vbs|vbe)/ nocase    // drive: D:\ + chars + ext

// ✓ BEST — combine into one alternation regex (no nested boolean, no trailing \\)
$e.target.file.full_path = /\\[Tt]emp.*\.(exe|dll)|\\\\.*\.(vbs|vbe)|[d-zD-Z]:\\.*\.(vbs|vbe)/ nocase
```

---

## String Literals

Use double quotes. Backslash-escape special characters.

```yara
$e.principal.hostname = "my-server"
$e.target.url = "https://example.com"
```

---

## Regular Expression Literals

Enclose in forward slashes. Use `nocase` for case-insensitive matching.

```yara
$e.target.process.command_line = /powershell.*-enc/
$e.target.url = /phishing/i        // ❌ /i flag not valid — use nocase instead
$e.target.url = /phishing/ nocase  // ✓ correct
```

**Regex in events:** Use `=` with a regex literal.
**Regex functions:** `re.regex()`, `re.capture()`, `re.replace()` — see `functions.md`.

---

## Enumerated Types

Fields with predefined value sets (like `metadata.event_type`, `security_result.action`)
cannot be matched with regex literals — use exact string values:

```yara
$e.metadata.event_type = "USER_LOGIN"          // ✓ correct
$e.metadata.event_type = /USER_.*/             // ✗ invalid — enumerated field
$e.security_result.action = "BLOCK"            // ✓
```

To match multiple values, use `or`:
```yara
($e.metadata.event_type = "USER_LOGIN" or
 $e.metadata.event_type = "USER_LOGOUT")
```

---

## Reference Lists and Data Tables

### Reference lists (single-column)

```yara
// String list
$e.principal.hostname in %string_list_name
$e.principal.hostname not in %string_list_name

// Regex list
$e.principal.hostname in regex %regex_list_name

// CIDR list
$e.principal.ip in cidr %cidr_list_name
```

### Data tables (multi-column)

```yara
// Column-specific matching
$e.target.hostname in %table_name.column_name
$e.target.hostname in regex %table_name.column_name
$e.principal.ip in cidr %table_name.cidr_column

// Assign a column value to a variable (for use in outcome/condition)
$category = $e.target.url in %url_categories.url_category
```

Reference lists and data tables are valid in `events:` and `outcome:` sections.

---

## YARA-L Map Support

For `Struct` and `Label` UDM field types, use map syntax:

```yara
// Struct field (additional.fields)
$e.additional.fields["pod_name"] = "kube-scheduler"

// Label field (ingestion_labels, etc.)
$e.metadata.ingestion_labels["MetadataKeyDeletion"] = "startup-script"
$e.target.resource.attribute.labels["role"] = "admin"
```

---

## Variable Types Quick Reference

| Type | Prefix | Defined in | Purpose |
|---|---|---|---|
| Event variable | `$e`, `$login` | `events:` | Represents a stream of events; prefix for field access |
| Placeholder variable | `$user`, `$ip` | `events:` + `match:` | Join key; group-by field |
| Match variable | same as placeholder | `match:` | Used as grouping key in match window |
| Outcome variable | `$count`, `$score` | `outcome:` | Computed aggregate; referenced in `condition:` with `$` |

**Event sources (explicit or implicit):**
```yara
$e.metadata.event_type = "USER_LOGIN"          // implicit UDM source
$e:udm.metadata.event_type = "USER_LOGIN"      // explicit UDM source
$e:graph.entity.hostname = "server-01"         // explicit Entity (ECG) source
```

---

## Function-to-Placeholder Assignment

Assign a function result to a placeholder variable in `events:`:

```yara
$hostname_lower = strings.to_lower($e.principal.hostname)
$entropy = math.round(strings.shannon_entropy($e.target.file.full_path), 2)
```

The variable can then be used in `match:`, `outcome:`, or `condition:`.

---

## Comments

```yara
// Single-line comment
/* Multi-line
   comment */
```

---

## `any` and `all` Keywords

For repeated (array) fields:

```yara
// True if ANY value in the repeated field satisfies the condition
any $e.target.ip in %suspicious_ips
any $e.about.hostname = "malicious-host"

// True if ALL values satisfy the condition
all $e.target.ip in cidr %internal_ranges
```

---

## Raw Log Filters

```yara
raw = "mimikatz"                 // string match in raw log
raw = /admin\$/ nocase           // regex match in raw log
raw = /./ AND parsed = false     // find raw logs that were NOT successfully parsed
```

`parsed = false` is a special boolean condition that filters to raw log entries where
the parser did not successfully extract UDM fields. Useful for diagnosing parsing gaps.

---

## `not` with Reference Lists

```yara
$e.principal.hostname not in %allowlisted_hosts
$e.principal.ip not in cidr %internal_cidrs
```
