# Code-Review-Comment-Classifier


Classifies GitHub code-review comments into **BUG, STYLE, PERFORMANCE, SECURITY, PRAISE**
using one regular expression set per category, combined into a single NFA-style machine.

## Run
```
python classifier.py comments.csv
```
CSV needs a `comment` column; an optional `label` column (hand-labelled ground truth)
turns on the accuracy report, per-category precision/recall and the confusion matrix.
Use `--comment-col` / `--label-col` if your headers differ.

## Tie-breaking
1. Category with the most distinct matched patterns wins.
2. Ties are broken by priority: SECURITY > BUG > PERFORMANCE > STYLE > PRAISE.
3. No match -> `UNKNOWN`.

`comments.csv` holds the 30 hand-labelled GitHub review comments (columns: id, comment, label, source_url).