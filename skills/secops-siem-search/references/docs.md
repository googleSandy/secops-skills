# SecOps SIEM Search: Live Documentation Sources

When looking up specific details (field names, function signatures, syntax rules), attempt to
fetch the live doc first using WebFetch or Bash (`curl`). Fall back to the static reference
files in this directory if the fetch fails.

**Note on renderability:** Most Google SecOps docs pages are server-side rendered and fetch
cleanly with WebFetch or `curl`. Two exceptions:
- **Premium/Standard parser split page** — server-side rendered ✅ — curl works, use for refresh
- **Full parser list (951 entries)** — paginated/dynamic ❌ — use the static reference files

## URL Map

| Topic | Live URL | Static fallback |
|---|---|---|
| **Parser-specific UDM field mappings** | `https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/{parser-slug}` | none — always fetch live |
| **Full parser list (951 log types)** | https://docs.cloud.google.com/chronicle/docs/ingestion/parser-list/supported-default-parsers | `all-log-types.md` (via lookup script) |
| **UDM field list (authoritative schema)** | https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list | `udm-fields.md` |
| UDM usage guide (namespace overview) | https://docs.cloud.google.com/chronicle/docs/unified-data-model/udm-usage | `udm-fields.md` |
| Search best practices & high-performance fields | https://docs.cloud.google.com/chronicle/docs/investigation/udm-search-best-practices | `best-practices.md` |
| Aggregate functions & stats queries | https://docs.cloud.google.com/chronicle/docs/investigation/statistics-and-aggregations-yara-l | `functions.md` |
| Joins (event-event, ECG, datatable) | https://docs.cloud.google.com/chronicle/docs/investigation/search-joins | `best-practices.md` |
| Raw log search syntax | https://docs.cloud.google.com/chronicle/docs/investigation/search-raw-logs | `SKILL.md` (inline) |
| Raw log search in Investigate UI | https://docs.cloud.google.com/chronicle/docs/investigation/raw-log-search-in-investigate | `SKILL.md` (inline) |
| YARA-L 2.0 syntax reference | https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax | `functions.md` |
| YARA-L 2.0 functions | https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-functions | `functions.md` |

## Community & Reference Resources

| Topic | URL | Static fallback |
|---|---|---|
| YARA-L cheat sheet (PDF) | https://github.com/Matchistador/Yara-L/blob/main/YARA-L%20cheat%20sheet.pdf | `best-practices.md` |
| Metrics in YARA-L rules (Part 1) — network bytes | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-using-metrics-in-yara-l-rules-part-1-4018 | `functions.md` |
| Metrics in YARA-L rules (Part 2) — auth & endpoint | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-using-metrics-in-yara-l-rules-part-2-4019 | `functions.md` |
| Metrics in YARA-L rules (Part 3) — advanced patterns | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-using-metrics-in-yara-l-rules-part-3-4021 | `functions.md` |
| select / unselect keywords in search | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-select-unselect-choosing-what-matters-5666 | `best-practices.md` |
| Time windows — tumbling, hop, sliding | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-this-charming-span-bucketing-events-in-time-windows-6463 | `best-practices.md` |
| Z-score anomaly detection with multi-stage | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-sweet-dreams-are-made-of-zs-6547 | `best-practices.md` |
| When to use multi-stage vs statistical search | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-should-i-stage-or-should-i-go-6387 | `best-practices.md` |
| timestamp.diff function | https://security.googlecloudcommunity.com/community-blog-42/new-to-google-secops-what-difference-does-it-make-3921 | `functions.md` |

## Fetch Strategy

When a user asks about a specific field, function, or capability:

1. Identify the relevant URL from the table above
2. Fetch it: `WebFetch(url, "Extract [specific topic] syntax, fields, and examples")`
3. If WebFetch returns navigation/empty content, try Bash: `curl -s "<url>" | ...`
4. If both fail, use the static fallback file and note the answer is from cached reference

## Refreshing the Parser Reference Files

The `all-log-types.md` file changes as Google adds new parsers. The premium/standard split page is server-side rendered and fetchable without
special tooling. To refresh:

**Using WebFetch:**
```
WebFetch(
  "https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/default-parser-configuration",
  "Extract the Premium Parsers and Standard Parsers sections with all product names and log_type values"
)
```

**Using Bash (curl):**
```bash
curl -s "https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/default-parser-configuration" \
  | python3 -c "
import sys, re
html = sys.stdin.read()
# Extract Premium section
m = re.search(r'<h2[^>]*>Premium Parsers.*?<h2[^>]*>Standard Parsers', html, re.DOTALL)
if m:
    links = re.findall(r'href=\"(/chronicle/docs/ingestion/default-parsers/[^\"]+)\"[^>]*>([^<]+)', m.group(0))
    for href, name in links:
        print(name.strip())
"
```

After fetching fresh content that differs from the static files, update the relevant `.md`
file so future agents benefit from the correction.

## Updating Static Files

If you successfully fetch fresh content that contradicts or extends the static reference files,
update the relevant `.md` file in this directory so future agents benefit from the correction.
