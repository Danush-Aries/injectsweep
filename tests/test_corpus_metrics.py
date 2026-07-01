"""Precision / recall over the labelled corpus.

Two metrics:

* Per-rule recall -- every expected rule ID in labels.json must be detected in its
  file (findings may be a superset; extra related findings are allowed).
* Binary detection -- malicious files must produce >=1 finding, clean files zero.
  From this we compute precision & recall and assert a perfect score on the
  shipped corpus.
"""

from __future__ import annotations

import os


def _metrics(labels, scan):
    from tests.conftest import CORPUS

    tp = fp = fn = tn = 0
    missing_rules = []
    for fname, expected in labels.items():
        result = scan(os.path.join(CORPUS, fname))
        got = {f.rule_id for f in result.findings}
        if expected:  # malicious
            for rid in expected:
                if rid not in got:
                    missing_rules.append((fname, rid, sorted(got)))
            if result.findings:
                tp += 1
            else:
                fn += 1
        else:  # clean control
            if result.findings:
                fp += 1
            else:
                tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return precision, recall, missing_rules, (tp, fp, fn, tn)


def test_per_rule_recall_complete(labels):
    from injectsweep.scanner import scan_file

    _, _, missing, _ = _metrics(labels, scan_file)
    assert not missing, f"expected rules not detected: {missing}"


def test_binary_precision_recall_perfect(labels):
    from injectsweep.scanner import scan_file

    precision, recall, _, counts = _metrics(labels, scan_file)
    tp, fp, fn, tn = counts
    assert precision == 1.0, f"precision {precision} (tp={tp}, fp={fp})"
    assert recall == 1.0, f"recall {recall} (tp={tp}, fn={fn})"
    # sanity: corpus actually contains both classes
    assert tp >= 15 and tn >= 5


def test_report_metrics_visible(labels, capsys):
    """Emit the metrics so `pytest -s` doubles as the precision/recall report."""
    from injectsweep.scanner import scan_file

    precision, recall, _, (tp, fp, fn, tn) = _metrics(labels, scan_file)
    print(
        f"\ninjectsweep corpus metrics: precision={precision:.3f} recall={recall:.3f} "
        f"(TP={tp} FP={fp} FN={fn} TN={tn})"
    )
    assert True
