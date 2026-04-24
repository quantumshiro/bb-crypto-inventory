# Phase04 Scoring Specification

Phase04 scoring treats each runtime vulnerability as one expected validation unit.

## Matching Rules

A validation is a true positive when all of the following hold:

1. `endpoint_url`, `category`, and `algorithm` match the ground-truth target.
2. The validation evidence satisfies the Phase04 evidence contract.
3. The validation confidence meets the target's minimum confidence threshold for calibration reporting.

Duplicate validations for the same expected unit are counted as duplicate false positives. Validations outside the selected target set are false positives. Missing expected validations are false negatives.

## Metrics

The runner reports precision, recall, F1, confidence calibration, per-channel counts, negative-control results, and budget compliance. The release gate requires high recall and precision, zero negative-control false positives, and budget compliance across repeated runs.
