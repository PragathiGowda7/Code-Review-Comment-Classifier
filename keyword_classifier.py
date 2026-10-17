import csv
import sys

KEYWORDS = {
    "SECURITY": [
        "security", "vulnerability", "vulnerabilities",
        "attacker", "password", "hardcoded", "injection",
        "xss", "cve", "untrusted", "ddos", "exploit"
    ],
    "BUG": [
        "bug", "error", "fails", "failing", "failed",
        "incorrect", "wrong", "broken", "crash",
        "exception", "regression", "out-of-range",
        "would still", "would skip", "prevents"
    ],
    "PERFORMANCE": [
        "slow", "cache", "performance", "efficient",
        "efficiency", "bottleneck", "overhead",
        "memory", "optimize", "copied before"
    ],
    "STYLE": [
        "typo", "readable", "formatting", "rename",
        "naming", "unrelated", "stale", "unclear",
        "documentation", "indentation"
    ],
    "PRAISE": [
        "nice", "great", "good", "excellent",
        "thank", "thanks", "lgtm", "love that",
        "well done", "improvements"
    ]
}

PRIORITY = [
    "SECURITY", "BUG", "PERFORMANCE", "STYLE", "PRAISE"
]


def classify(comment):
    text = comment.lower()
    scores = {}

    for category in PRIORITY:
        scores[category] = sum(
            1 for word in KEYWORDS[category]
            if word in text
        )

    best_score = max(scores.values())

    if best_score == 0:
        return "UNKNOWN"

    for category in PRIORITY:
        if scores[category] == best_score:
            return category


def main():
    filename = sys.argv[1] if len(sys.argv) > 1 else "comments.csv"

    with open(filename, "r", encoding="utf-8-sig", newline="") as file:
        sample = file.read(2048)
        file.seek(0)

        dialect = csv.Sniffer().sniff(sample, delimiters=",\t")
        reader = csv.DictReader(file, dialect=dialect)

        rows = list(reader)

    correct = 0
    evaluated = 0

    for row in rows:
        comment = row.get("comment", "").strip()
        actual = (row.get("label") or "").strip().upper()

        predicted = classify(comment)

        if actual:
            evaluated += 1
            if predicted == actual:
                correct += 1
                result = "OK"
            else:
                result = "WRONG"
        else:
            result = "NO LABEL"

        print(
            f"Comment {row.get('id', '?')} -> "
            f"{predicted} | Actual: {actual or 'MISSING'} | {result}"
        )

    print("\nKEYWORD CLASSIFIER RESULTS")
    print(f"Total comments: {len(rows)}")
    print(f"Comments with labels: {evaluated}")
    print(f"Correct predictions: {correct}")
    if evaluated:
        print(f"Accuracy: {correct}/{evaluated} = {correct/evaluated:.1%}")


if __name__ == "__main__":
    main()
