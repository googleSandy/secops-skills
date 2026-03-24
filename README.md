# 🛡️ SecOps Agent Skills

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Updater](https://img.shields.io/badge/Automated_Updates-Active-success)](.github/workflows/update-references.yml)
[![Agent Skills](https://img.shields.io/badge/Agent_Skills-Compatible-5865F2)](https://agentskills.io)
[![SecOps](https://img.shields.io/badge/Google-SecOps-4285F4)](https://cloud.google.com/security/products/security-operations)

Agent Skills for [Google Security Operations](https://cloud.google.com/security/products/security-operations) (SecOps / Chronicle) — giving AI agents accurate, up-to-date knowledge to write SIEM queries, build detection rules, and navigate the detection engineering workflow.

Built to the [Agent Skills](https://agentskills.io) open specification — works with any agent that supports it.

---

## 📚 Skills

### [`secops-siem-search`](skills/secops-siem-search/SKILL.md)

Syntax reference and field guidance for authoring SecOps SIEM queries for investigations and threat hunting.

Covers: UDM filter queries · stats/aggregation · event-event joins · raw log search · reference list lookups · entity investigations · enriched data (geolocation, VirusTotal) · entity context (`graph.*`) · data availability timing

<img width="804" height="629" alt="image" src="https://github.com/user-attachments/assets/c03058a4-9203-4f3b-85d5-eae2917d2fdb" />


### [`secops-yara-l`](skills/secops-yara-l/SKILL.md)

Syntax reference and patterns for authoring YARA-L 2.0 detection rules and search queries. Rules should always be tested in your environment before deployment.

Covers: single-event rules · multi-event correlation · sliding/tumbling/hop windows · composite rules · outcome aggregations · multi-stage search queries · Z-score and MAD anomaly detection · entity graph joins · metrics behavioral analytics

### [`secops-detection-engineering`](skills/secops-detection-engineering/SKILL.md)

Knowledge and guidance for the SecOps detection engineering workflow — from writing a rule to getting it into production.

Covers: understanding the rule lifecycle (test → retrohunt → deploy) · choosing run frequency · diagnosing detection delays · MTTD optimization · context-aware analytics · risk scoring · Safe Browsing and threat intel IOC joins · composite detection chains · troubleshooting compilation and runtime errors

---

## 🚀 Installation

Clone the repo and point your agent at the `skills/` directory:

```bash
git clone https://github.com/googleSandy/secops-skills.git
```

Each skill is a self-contained directory under `skills/`. How you load them depends on your agent:

- **Agent Skills-compatible agents** — configure your agent to load skills from `secops-skills/skills/`, or copy individual skill directories into your agent's skills path (e.g. `~/.agents/skills/`, `~/.claude/skills/`, or wherever your agent looks)
- **Other agents** — drop the skill directory alongside your project and reference the `SKILL.md` in your system prompt or context

Each skill is independent — install one, two, or all three depending on what you need.

---

## 📁 Structure

```
secops-skills/
├── llms.txt                          # Skill index for LLM discovery
├── scripts/
│   └── update_references.py          # Maintenance: fetch fresh docs from Google
├── .github/workflows/
│   └── update-references.yml         # Automated bi-weekly reference refresh
└── skills/
    ├── secops-siem-search/
    │   ├── SKILL.md                  # Skill entry point
    │   ├── evals/evals.json          # Test cases for evaluation
    │   └── references/               # On-demand reference files
    │       ├── docs.md               # Live documentation URLs + refresh instructions
    │       ├── all-log-types.md      # All 1000+ supported log types (searched via lookup script)
    │       ├── all-log-types.md      # All 1000+ supported log types
    │       ├── udm-fields.md         # Full UDM schema and event types
    │       ├── functions.md          # Aggregate + built-in functions
    │       ├── best-practices.md     # Query performance and section order
    │       ├── enriched-data.md      # Geolocation and VirusTotal fields
    │       ├── entity-context.md     # graph.* namespace reference
    │       ├── data-availability.md  # When data is searchable by method
    │       └── raw-log-search.md     # RE2 regex, limits, optimization
    ├── secops-yara-l/
    │   ├── SKILL.md
    │   ├── evals/evals.json
    │   └── references/
    │       ├── cheat-sheet.md        # Quick syntax reference
    │       ├── syntax.md             # Full section-by-section syntax
    │       ├── expressions.md        # Operators, regex, maps, any/all
    │       ├── functions.md          # All YARA-L functions
    │       ├── examples.md           # Production rules from chronicle/detection-rules
    │       ├── multi-stage.md        # Multi-stage queries, MAD, Z-score
    │       └── best-practices.md     # Known issues and performance tips
    └── secops-detection-engineering/
        ├── SKILL.md
        ├── evals/evals.json
        └── references/
            ├── workflow.md           # Rule lifecycle: create → test → retrohunt → deploy
            ├── delays-and-performance.md  # Detection latency and MTTD
            ├── context-and-risk.md   # Entity graph, Safe Browsing, threat intel
            ├── troubleshooting.md    # Runtime error table and fixes
            ├── composite-detections.md    # Composite rule patterns
            └── docs.md               # Live documentation URLs
```

---

## 🔄 Keeping References Up to Date

Reference files (log types, UDM fields, YARA-L functions) are scraped from Google's live documentation. They can go stale as Google updates their docs.

### Automated (GitHub Actions)

The included workflow runs automatically on the 1st and 15th of every month. If the source documentation has changed, it fetches the updated content and commits it. You can also trigger it manually from the Actions tab.

### Manual

```bash
python3 scripts/update_references.py
```

No dependencies — uses Python 3 standard library only (`urllib`, `html.parser`). The script checks the `Last Updated` timestamp on each source page before fetching — it skips files that haven't changed, so it's safe to run frequently.

### How it works

The update script uses **timestamp-based diffing** — it reads the `Last Updated` date from each Google documentation page and compares it to the date stored in the local reference file. Only changed files are re-fetched and rewritten. This keeps network requests minimal and avoids unnecessary commits.

**Important:** The update script is a maintenance tool for humans and CI, not for agents. Skills do not instruct agents to run it. If an agent needs to verify whether a reference file is current, it should consult `references/docs.md` for the source URL and check it directly.

---

## 🧪 Evaluation

Each skill includes test cases in `evals/evals.json` following the [AgentSkills evaluation format](https://agentskills.io/skill-creation/evaluating-skills). Results comparing with-skill vs. without-skill are in `evals-workspace/`.

To run evals, follow the [AgentSkills evaluation guide](https://agentskills.io/skill-creation/evaluating-skills).

---

## ⚙️ Compatibility

- **Google SecOps (SecOps / Chronicle) SIEM** required
- **Detection Engine** required for `secops-yara-l` and `secops-detection-engineering`
- YARA-L version: 2.0
- ATT&CK version referenced: v14.1+

---

## 🤝 Contributing

Contributions welcome — especially:

- New production rule examples (see [`secops-yara-l/references/examples.md`](skills/secops-yara-l/references/examples.md))
- Additional gotchas discovered in production
- Corrections to UDM field documentation
- Eval test cases that expose skill gaps — open an issue with the following:
  - **Prompt** — the exact question or task you gave the agent
  - **Agent output** — what it produced
  - **Expected output** — what a correct response should look like
  - **Assertions** — specific, checkable statements about what the correct output must contain (e.g. "Rule uses `nocase` not `/i` flag", "Query does not use pipe syntax")

  Alternatively, submit a PR adding a test case directly to the relevant `evals/evals.json` file using the existing format.

Open an issue or PR. For new examples, please source them from the official [chronicle/detection-rules](https://github.com/chronicle/detection-rules) repo or from production environments you own.

---

## ⚖️ License

Apache 2.0 — see [LICENSE](LICENSE).

Rule examples sourced from [chronicle/detection-rules](https://github.com/chronicle/detection-rules) are also Apache 2.0.
