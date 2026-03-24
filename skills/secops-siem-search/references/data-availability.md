# SecOps SIEM: Data Availability Reference

This reference explains when ingested data becomes searchable, by search method.

Source: https://docs.cloud.google.com/chronicle/docs/investigation/expected-data-availability-for-search

---

## Search Method Availability Summary

| Search method | Searches | Available after ingestion |
|---|---|---|
| **Raw log search** | Original unparsed log text | **Immediately** — only requires ingestion |
| **UDM search** | Normalized + enriched UDM events | After full pipeline (see below) |
| **Natural language search (Gemini)** | Same as UDM search | After full pipeline |
| **SOAR search** | Cases and entities | After UDM + detection + alert + case creation |

---

## UDM Search Pipeline Stages

Data must pass through all stages before appearing in UDM search:

1. **Ingestion** — Raw log arrives at SecOps ingestion point
2. **Parsing** — Log type identified and processed by its parser
3. **Normalization** — Data extracted and mapped to UDM schema
4. **Indexing** — Normalized UDM record indexed for structured search
5. **Enrichment** — Context added: threat intelligence, geolocation, user/asset data

Only after step 5 is the data available in UDM search.

**Practical implication:** If you just ingested data and can't find it in UDM search, it
may still be in the pipeline. Use raw log search to verify ingestion succeeded.

---

## SOAR Search Pipeline

SOAR search adds additional stages on top of UDM availability:

1. *(All UDM pipeline stages above)*
2. **Detection** — A Detection Engine rule must match the UDM event(s)
3. **Alert generation** — System creates a formal alert from the detection match
4. **Case creation** — SOAR platform ingests the alert and creates a case

SOAR search queries cases and alerts — not raw logs or UDM events directly.

---

## Statistical Query Constraints

Stats queries (using `match:` / `outcome:` sections) have additional constraints:
- **Lookback limit:** Max 90 days of data per query
- **Availability delay:** Statistical data available **2 hours after ingestion** (not immediately)
- **Result limit:** Max 10,000 rows returned

---

## Diagnostic Pattern: Data Not Showing Up

```
// 1. Verify raw log ingested (immediate availability)
metadata.log_type = "YOUR_LOG_TYPE"
raw = "known_string_from_the_log"

// 2. If raw log found but UDM search shows nothing:
//    → Data is in the parsing/normalization pipeline
//    → Wait and retry UDM search

// 3. If raw log search also shows nothing:
//    → Ingestion issue — check ingestion pipeline
//    → Verify log source configuration
```

---

## Data Enrichment Timing

Enrichment (geolocation, VirusTotal) is added as part of step 5 of the UDM pipeline.
A UDM event may appear in search before enrichment completes — enriched fields
(`ip_geo_artifact.*`, VirusTotal context) may be absent on very recent events.

If enriched fields are empty on recent data, the event may still be in the enrichment
stage. Query again after a few minutes.
