# injectsweep

**A static linter that catches prompt-injection payloads hidden in documents *before* they poison your RAG index.**

[![CI](https://github.com/Danush-Aries/injectsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/Danush-Aries/injectsweep/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![owasp](https://img.shields.io/badge/OWASP-LLM01-purple)

> Offline. No API keys. No network calls. It statically analyses the real bytes of real documents.

---

## The threat: indirect prompt injection via your own knowledge base

Retrieval-Augmented Generation (RAG) pipelines ingest documents — PDFs, wiki pages,
support tickets, spreadsheets — and feed their text to an LLM at answer time. That
makes **every ingested document an untrusted input channel**. An attacker who can
get one poisoned file into your corpus (a résumé, a KB article, a CSV export) can
plant an instruction that is *invisible to the human who approves the document* but
fully readable by the model:

- white-on-white or 1px text in an HTML page,
- an instruction inside an HTML comment or a PDF annotation,
- a zero-width / Unicode-Tag-block message smuggled into a CSV cell,
- a base64- or rot13-wrapped payload that slips past keyword filters.

This is **OWASP LLM01: Prompt Injection (indirect)**. Once embedded, the payload sits
in your vector store and fires whenever it's retrieved.

### Why this tool exists (the gap)

Every popular LLM-security tool operates at **runtime, on live prompts**:

| Tool | Stars | Operates on |
|------|------:|-------------|
| garak | 8.3k | live model probing |
| llm-guard | 3.1k | runtime prompt/response |
| rebuff | ~1.2k | runtime prompt |
| promptmap | ~1k | runtime prompt |

**None of them statically scan the documents entering the pipeline.** The only tools
that do are tiny and format-limited (pdf-injection-scanner ~11★, phantom-lint ~4★).
`injectsweep` owns the **pre-ingestion input-firewall layer**: a linter you run in CI
or in your ingestion job, across PDF/HTML/DOCX/Markdown/CSV/text, that blocks poisoned
documents before they're ever chunked and embedded.

---

## 5-second demo: watch it catch the invisible instruction

`corpus/blog_tinyfont.html` looks like an innocent cooking-tips page. Hidden in a
`font-size:1px` span is an instruction no reader will ever see:

```console
$ injectsweep scan corpus/blog_tinyfont.html
corpus/blog_tinyfont.html  (html)
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━┳────────────────────────────────────┐
┃ Severity ┃ Rule                        ┃ Layer     ┃ Where ┃ Finding                            ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━╇────────────────────────────────────┩
│ CRITICAL │ ISW020 imperative-injection │ tiny_font │ span  │ Prompt-injection phrasing          │
│          │                             │           │       │ [ignore-previous-instructions]:    │
│          │                             │           │       │ 'Ignore all previous instructions' │
│          │                             │           │       │ (found in a human-invisible layer) │
│ MEDIUM   │ ISW012 tiny-font-text       │ tiny_font │ span  │ Human-invisible text in the        │
│          │                             │           │       │ 'tiny_font' layer; a reader never  │
│          │                             │           │       │ sees it, a RAG ingester keeps it.  │
└──────────┴─────────────────────────────┴───────────┴───────┴────────────────────────────────────┘

Summary: 2 finding(s) across 1/1 file(s); max severity = CRITICAL
```

Run it on a real clean document and it stays quiet:

```console
$ injectsweep scan corpus/clean_article.html
injectsweep: no injection indicators in 1 file(s).
```

---

## Quickstart

```bash
git clone https://github.com/Danush-Aries/injectsweep
cd injectsweep
pip install -e .

# scan the bundled example corpus (20 planted payloads + 6 clean controls)
injectsweep scan corpus/

# machine-readable outputs
injectsweep scan corpus/ --format json
injectsweep scan corpus/ --format sarif --output injectsweep.sarif

# CI gate: exit non-zero if anything at/above HIGH is found
injectsweep scan ./incoming_docs --fail-on high
```

### Use it as a library / input firewall

```python
from injectsweep import pre_ingest, Severity

result = pre_ingest("incoming/customer_upload.pdf")   # path or raw bytes
if result.max_severity >= Severity.HIGH:
    reject(result)          # block it before chunk + embed
    for f in result.findings:
        log.warning("%s %s [%s] %s", f.severity.label, f.rule_id, f.layer, f.message)
```

---

## Detector catalog

Extractors surface both the **visible** text and **hidden layers** (HTML comments,
white/tiny/off-canvas CSS text, PDF annotations, document metadata, Word "vanished"
runs). Detectors then run genuine static analysis over every layer. An imperative
found in a *hidden* layer is escalated to **CRITICAL** — that is the textbook
indirect-injection primitive.

| Rule | Name | Severity | What it catches |
|------|------|----------|-----------------|
| ISW001 | zero-width-characters | medium | ZWSP/ZWNJ/ZWJ/BOM/word-joiner smuggling |
| ISW002 | unicode-tag-smuggling | critical | U+E0000–E007F Tag block (decoded back to ASCII) |
| ISW003 | bidi-override | high | RLO/LRO/isolate characters that reorder text |
| ISW004 | variation-selector-smuggling | medium | U+FE00–FE0F / U+E0100–E01EF hidden bytes |
| ISW005 | homoglyph-confusable | low | mixed-script tokens imitating ASCII (Cyrillic/Greek) |
| ISW010 | hidden-html-comment | medium | instructions inside `<!-- ... -->` |
| ISW011 | white-on-white-text | medium | foreground colour ≈ background |
| ISW012 | tiny-font-text | medium | text set at ≤4px |
| ISW013 | offscreen-text | medium | absolute/indent/margin pushed off-canvas |
| ISW014 | hidden-layer-text | medium | text in a non-visible layer (vanished run, etc.) |
| ISW020 | imperative-injection | high | "ignore previous instructions", "disregard", … |
| ISW021 | system-prompt-override | high | role redefinition, "reveal your system prompt" |
| ISW030 | data-exfil-image-beacon | high | markdown/HTML image beacon to an external host |
| ISW031 | suspicious-url | medium | URLs carrying base64 blobs / exfil query params |
| ISW040 | encoded-payload | low | base64/hex blob that decodes to readable text |
| ISW041 | nested-encoded-injection | critical | injection recovered after **recursive** decoding |

Formats parsed: **PDF** (pypdf), **HTML** (BeautifulSoup), **DOCX** (python-docx),
**Markdown**, **CSV**, **plain text**.

---

## Accuracy on the example corpus

`corpus/` ships **20 hand-crafted malicious documents** (one per payload class, across
all six formats) and **6 clean control documents**, each mapped to its expected
finding IDs in [`corpus/labels.json`](corpus/labels.json). Every payload is a benign
demo — the only "exfil" host used anywhere is `example.com` (reserved by RFC 2606).

Measured by `tests/test_corpus_metrics.py`:

```
precision = 1.000   recall = 1.000   (TP=20  FP=0  FN=0  TN=6)
```

- **Recall 1.0** — every planted payload is caught.
- **Precision 1.0** — zero false positives on the clean controls.

(Metrics are computed on a deliberately curated corpus; see *Limitations*.)

---

## SARIF + GitHub code scanning

`--format sarif` emits a valid **SARIF 2.1.0** log (validated in CI against the
official OASIS/SchemaStore schema), so findings show up natively in the GitHub
**Security → Code scanning** tab.

### GitHub Action

```yaml
# .github/workflows/injection-scan.yml
name: injection-scan
on: [pull_request]
jobs:
  injectsweep:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: Danush-Aries/injectsweep@main
        with:
          path: ./knowledge_base     # documents about to be ingested
          fail-on: high              # block the PR on high/critical findings
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: injectsweep.sarif
```

---

## How it works

```
             ┌────────────┐     ┌──────────────────────────┐     ┌───────────┐
  file bytes │ extractors │ --> │ segments (visible/hidden)│ --> │ detectors │ --> findings
             └────────────┘     └──────────────────────────┘     └───────────┘
              pdf/html/docx        layer-tagged provenance         static analysis
              md/csv/text          (comment, white_text, …)        (regex/unicode/decode)
                                                                        │
                                                          reporters: table · json · SARIF 2.1.0
```

The `pre_ingest(path_or_bytes)` API is the intended integration point: call it in
your ingestion job and reject anything above your severity threshold.

---

## Development

```bash
pip install -e ".[dev]"   # installs pytest + jsonschema + fpdf2 (corpus generator)
pytest                    # 58 tests: golden files, format matrix, recursive decoding,
                          # zero-FP controls, SARIF schema validation, precision/recall
python corpus/_generate.py   # regenerate the example corpus from source
```

---

## Limitations (honest)

- **Detection is signature/heuristic-based**, not semantic. A novel phrasing that
  matches none of the imperative patterns can slip past ISW020/021 — though the
  *structural* signals (hidden layers, invisible unicode, encoded blobs) catch most
  delivery vectors regardless of wording.
- **PDF colour is not recovered per-glyph.** injectsweep extracts all PDF text and
  relies on the content detectors; a "white text" PDF is caught because its payload
  is an imperative, not because the colour is measured.
- **The corpus is curated.** Perfect precision/recall demonstrates the detectors work
  against known payload classes; it is not a claim of 100% accuracy on arbitrary
  real-world documents.
- **English-centric** imperative patterns today. Homoglyph/unicode/encoding detectors
  are language-agnostic; the phrase list is not.
- **No macro / embedded-object execution analysis** (e.g. OLE, JS in PDF). Scope is
  *text-layer* injection, which is the RAG-poisoning threat.

---

## Author

**Dhanush Shankar** — B.Tech CSE '26, focused on AI security.
Built as a flagship AI-security project. Contributions and issues welcome.

## License

MIT © 2026 Dhanush Shankar
