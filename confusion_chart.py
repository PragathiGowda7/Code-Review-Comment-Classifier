import csv
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from classifier import classify


actual_categories = ["BUG", "STYLE", "PERFORMANCE", "SECURITY", "PRAISE"]
predicted_categories = actual_categories + ["UNKNOWN"]
counts = np.zeros((len(actual_categories), len(predicted_categories)), dtype=int)

with Path(__file__).with_name("comments.csv").open(
    newline="", encoding="utf-8-sig"
) as csv_file:
    reader = csv.DictReader(csv_file, delimiter="\t")
    for row in reader:
        actual = (row.get("label") or "").strip().upper()
        if not actual:
            continue
        if actual not in actual_categories:
            raise ValueError(f"Unknown actual category: {actual}")

        comment = (row.get("comment") or "").strip()
        predicted, _, _ = classify(comment)
        counts[actual_categories.index(actual), predicted_categories.index(predicted)] += 1

plt.imshow(counts, cmap="Blues")
plt.xticks(range(len(predicted_categories)), predicted_categories)
plt.yticks(range(len(actual_categories)), actual_categories)
plt.xlabel("Predicted category")
plt.ylabel("Actual category")
plt.title("Confusion Matrix - Code Review Comment Classifier")

for row in range(counts.shape[0]):
    for column in range(counts.shape[1]):
        plt.text(column, row, str(counts[row, column]), ha="center", va="center")

plt.tight_layout()
plt.savefig(Path(__file__).with_name("confusion_matrix.png"))
print("Saved confusion_matrix.png")
