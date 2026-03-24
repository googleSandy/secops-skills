"""
update_references.py — fetch live Google SecOps documentation and update reference files.

No third-party dependencies. Uses only Python 3 standard library (urllib, html.parser).

Usage:
    python3 scripts/update_references.py

Run manually or via the included GitHub Actions workflow (.github/workflows/update-references.yml).
Uses timestamp-based diffing: skips files that haven't changed on the source page.
"""

import os
import re
import sys
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.request import urlopen, Request
from urllib.error import URLError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

# Map of output files → source URLs and extraction config.
# extract_section: h2 id anchor to start extraction from (None = full page tables).
# Only the premium/standard split page and the parser list are updated automatically.
# Other reference files (udm-fields, functions) are curated manually — their source
# pages are JS-rendered or too large to reliably extract with stdlib tools.
DOCS_MAP = {
    os.path.join(PROJECT_ROOT, "skills/secops-siem-search/references/all-log-types.md"): {
        "url": "https://docs.cloud.google.com/chronicle/docs/ingestion/parser-list/supported-default-parsers",
        "title": "SecOps: All Supported Log Types",
        "header": "SecOps: All Supported Log Types\n\n"
                  "Complete list of all parsers with a `metadata.log_type` value.\n"
                  "For premium/standard tier split see `premium-log-types.md` and `standard-log-types.md`.\n\n"
                  "**Source:** https://docs.cloud.google.com/chronicle/docs/ingestion/parser-list/supported-default-parsers\n\n",
        "extract_section": None,
        "table_header": "| `metadata.log_type` | Vendor / Product |\n|---|---|\n",
        "extractor": "full_table",
    },
}


# ── HTML parsing ──────────────────────────────────────────────────────────────

class FullTableExtractor(HTMLParser):
    """
    Extracts log type entries from the full supported-default-parsers page.

    Page structure per row:
        <td>Product Name</td>
        <td>Category</td>
        <td><code translate="no">LOG_TYPE</code></td>
        <td>Format</td>

    Derives log type from the <code> element in the third column.
    """

    def __init__(self):
        super().__init__()
        self.entries = []
        self._cells = []
        self._cell_text = []
        self._code_text = []
        self._in_td = False
        self._in_code = False

    def handle_starttag(self, tag, attrs):
        if tag == 'tr':
            self._cells = []
        elif tag == 'td':
            self._in_td = True
            self._cell_text = []
            self._code_text = []
        elif tag == 'code' and self._in_td:
            self._in_code = True

    def handle_endtag(self, tag):
        if tag == 'td' and self._in_td:
            self._in_td = False
            self._in_code = False
            self._cells.append((''.join(self._cell_text).strip(),
                                 ''.join(self._code_text).strip()))
        elif tag == 'tr':
            if len(self._cells) >= 3:
                product = self._cells[0][0]
                log_type = self._cells[2][1]  # code content of third cell
                if re.match(r'^[A-Z][A-Z0-9_]{2,}$', log_type) and product:
                    self.entries.append((log_type, product))
            self._cells = []
        elif tag == 'code':
            self._in_code = False

    def handle_data(self, data):
        if self._in_td:
            self._cell_text.append(data)
        if self._in_code:
            self._code_text.append(data)


class LastUpdatedParser(HTMLParser):
    """Extracts the 'Last updated YYYY-MM-DD UTC' footer text from Google docs pages."""

    def __init__(self):
        super().__init__()
        self.result = None
        self._in_footer = False

    def handle_data(self, data):
        m = re.search(r'Last updated (\d{4}-\d{2}-\d{2})', data)
        if m:
            self.result = m.group(1)


class ParserListExtractor(HTMLParser):
    """
    Extracts log-type entries from the default-parser-configuration page.

    Google's page structure for each parser entry:
        <li><p><a href="/chronicle/docs/ingestion/default-parsers/...">Collect X logs</a></p></li>

    The href slug and link text let us derive both the log type name and product name.
    We extract entries that fall between the target section heading and the next h2.
    """

    def __init__(self, section_id):
        super().__init__()
        self.section_id = section_id      # e.g. "premium-parsers"
        self.entries = []                 # list of (log_type, product_name)
        self._in_target = False
        self._past_target = False
        self._depth = 0
        self._current_href = None
        self._current_text = []
        self._in_anchor = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        # Detect section heading by id
        if tag in ("h2", "h3") and attrs.get("id") == self.section_id:
            self._in_target = True
            return

        # Detect end of section (next h2)
        if tag == "h2" and self._in_target:
            self._in_target = False
            self._past_target = True
            return

        if not self._in_target:
            return

        if tag == "a" and "href" in attrs:
            self._current_href = attrs["href"]
            self._current_text = []
            self._in_anchor = True

    def handle_endtag(self, tag):
        if tag == "a" and self._in_anchor:
            self._in_anchor = False
            if self._current_href and self._current_text:
                self._process_entry()
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        if self._in_anchor:
            self._current_text.append(data)

    def _process_entry(self):
        href = self._current_href  # e.g. /chronicle/docs/ingestion/default-parsers/pan-prisma-cloud
        text = "".join(self._current_text).strip()

        # Derive log type from href slug: last path segment, uppercase, hyphens→underscores
        slug = href.rstrip("/").split("/")[-1]
        if not slug or "ingestion" not in href:
            return

        log_type = slug.upper().replace("-", "_")

        # Strip common prefixes from display text to get product name
        product = re.sub(r"^(Collect |Ingest |Configure )", "", text, flags=re.I)
        product = re.sub(r"\s+logs?$", "", product, flags=re.I)
        product = re.sub(r"\s+overview$", "", product, flags=re.I)
        product = product.strip()

        if log_type and product:
            self.entries.append((log_type, product))


# ── Network ───────────────────────────────────────────────────────────────────

def fetch(url, timeout=20):
    """Fetch a URL using urllib (stdlib). Returns HTML string or None on error."""
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; secops-skills-updater/1.0)"
    }
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except URLError as e:
        print(f"  ERROR fetching {url}: {e}", file=sys.stderr)
        return None


# ── Timestamp helpers ─────────────────────────────────────────────────────────

def get_live_timestamp(html):
    """Extract 'Last updated YYYY-MM-DD' from Google docs HTML."""
    p = LastUpdatedParser()
    p.feed(html)
    return p.result or datetime.now(timezone.utc).strftime("%Y-%m-%d")


def get_local_timestamp(path):
    """Read the stored Last Updated date from a local reference file."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.search(r'\*\*Last Updated:\*\*\s*(\d{4}-\d{2}-\d{2})', line)
            if m:
                return m.group(1)
    return None


# ── Extraction ────────────────────────────────────────────────────────────────

def extract_parser_entries(html, config):
    """Return list of (log_type, product_name) tuples using the configured extractor."""
    extractor_type = config.get("extractor", "section_links")

    if extractor_type == "full_table":
        p = FullTableExtractor()
        p.feed(html)
        return p.entries
    else:
        # section_links: extract <a href> links within a named h2 section
        p = ParserListExtractor(config["extract_section"])
        p.feed(html)
        return p.entries


def entries_to_markdown_table(entries, table_header):
    """Convert list of (log_type, product) tuples to a Markdown table."""
    if not entries:
        return ""
    rows = [f"| `{lt}` | {prod} |" for lt, prod in entries]
    return table_header + "\n".join(rows) + "\n"


# ── Main processing ───────────────────────────────────────────────────────────

def process(file_path, config):
    name = os.path.basename(file_path)
    print(f"Checking {name}...")

    html = fetch(config["url"])
    if not html:
        print(f"  Skipping — could not fetch source.")
        return

    live_ts = get_live_timestamp(html)
    local_ts = get_local_timestamp(file_path)

    if local_ts == live_ts:
        print(f"  Up to date ({live_ts}). Skipping.")
        return

    print(f"  Changed: local={local_ts} → live={live_ts}. Updating...")

    entries = extract_parser_entries(html, config)
    if not entries:
        print(f"  WARNING: no entries extracted for section '{config['extract_section']}'. "
              f"Page structure may have changed. Skipping write.")
        return

    table_md = entries_to_markdown_table(entries, config["table_header"])

    content = (
        f"# {config['title']}\n\n"
        f"> **Last Updated:** {live_ts}  \n"
        f"> **Source:** {config['url']}\n\n"
        f"{config['header']}"
        f"{table_md}"
    )

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"  Written: {len(entries)} entries.")


def main():
    print("SecOps reference updater (stdlib only — no pip required)\n")
    for path, config in DOCS_MAP.items():
        process(path, config)
    print("\nDone.")


if __name__ == "__main__":
    main()
