# SecOps SIEM: Raw Log Search Reference

Raw log search scans the **original unparsed log text**, before parsing and normalization.
Use it when the data you need isn't mapped to a UDM field.

Sources:
- https://docs.cloud.google.com/chronicle/docs/investigation/raw-log-search-in-investigate
- https://docs.cloud.google.com/chronicle/docs/investigation/search-raw-logs
- https://docs.cloud.google.com/chronicle/docs/investigation/filter-data-raw-log-scan-view

---

## Syntax

```
raw = "exact string match"
raw = /regex pattern/
raw = /case_insensitive_pattern/ nocase
```

**Constraints:**
- Max **150 characters** in the search expression
- String must be at least **4 characters** for legacy method
- Hard result cap: **10,000 entries** — returns a sample if exceeded

---

## Optimization

Raw log search is slower than UDM search because it scans unindexed text. Always optimize:

1. **Narrow time range** — smaller window = faster scan
2. **Specify log sources** — filter to one or more log types instead of scanning all
3. **Combine with UDM filter** — add `metadata.log_type` to pre-filter before raw scan:
   ```
   metadata.log_type = "WINEVTLOG"
   raw = /mimikatz|sekurlsa/ nocase
   ```
4. **Use specific regex** — `raw = /goo\w{3}\.com/` is faster than `raw = /goo.*/`

---

## RE2 Regex Syntax

SecOps uses Google RE2 regex engine. Common patterns:

| Pattern | Matches |
|---|---|
| `.` | Any single character |
| `{x}` | Exactly x of preceding |
| `[xyz]` | Character class: x, y, or z |
| `[^xyz]` | Not x, y, or z |
| `\d` | Digit |
| `\w` | Word character (letter, digit, underscore) |
| `\s` | Whitespace |
| `^` | Start of string |
| `$` | End of string |
| `a*` | Zero or more a |
| `a+` | One or more a |
| `a?` | Zero or one a |
| `(a\|b)` | a or b |
| `(?i)` | Case-insensitive flag (alternative to `nocase`) |

Full RE2 syntax: https://github.com/google/re2/wiki/Syntax

---

## Windows Log Examples (JSON format)

```
// Failed logon (Event ID 4625)
raw = /"EventID":4625/

// Powershell execution policy bypass
raw = /ExecutionPolicy.*Bypass/i

// Encoded PowerShell command
raw = /powershell.*-enc/i

// Mimikatz indicators
raw = /mimikatz|sekurlsa|wdigest/ nocase

// PsExec execution
raw = /"PsExec"/

// Pass-the-hash indicators
raw = /NtlmSsp|NTLM/ nocase

// Lateral movement via WMI
raw = /WmiPrvSE|wmic.*process.*call.*create/ nocase
```

---

## Results Behavior

Raw log search results combine:
1. **UDM events** — normalized events generated from matching raw logs
2. **Raw log lines** — the original log text that matched

Clicking a UDM result shows related events and the associated raw log.
Clicking a raw log line shows the full raw log entry and its source.

**Note:** Occasionally a UDM event may fail to display next to its raw log due to a
display limitation — this is not a parsing error.

---

## Downloading Results

From the Raw log results table: **Menu (⋮) → Download as CSV**

Default CSV columns: Timestamp, Event Type, Raw Log.
The Raw Log column is always included. Other columns can be added via Column Manager
but appear only in the table, not the CSV download.

To download UDM fields: run a UDM search, select columns, then download as CSV.

---

## Legacy Raw Log Search

The older prompt-based method (still available):
1. Enter a search string (min 4 chars) in the Search bar
2. If UDM search returns no results, a **Raw log search** option appears
3. Optionally specify Start/End time (default: last 7 days) and log sources
4. Click Search

The recommended method is the `raw =` format in the main search bar — it's faster
and supports full regex syntax without the 4-character minimum constraint on regex.
