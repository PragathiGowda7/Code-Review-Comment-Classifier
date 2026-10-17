"""
Code Review Comment Classifier  (regex / NFA based)

Every category (BUG, STYLE, PERFORMANCE, SECURITY, PRAISE) owns a list of
regular expressions.A regular expression is equivalent to an NFA, and the
union (|) of NFAs is again an NFA, so all patterns are also combined into
ONE big machine (COMBINED_NFA) in which every alternative is tagged with the
name of its category.A comment is "accepted" when that machine reaches an
accepting state, i.e. at least one pattern matches.

Tie-breaking :
    1. The category with the MOST distinct matched patterns wins.
    2. If the counts are tied, PRIORITY order decides:
       SECURITY > BUG > PERFORMANCE > STYLE > PRAISE   (more serious wins)
    3. If nothing matches the label is UNKNOWN.

Usage:
    python classifier.py comments.csv
    python classifier.py comments.csv --comment-col comment --label-col label
    python classifier.py comments.csv --no-matrix

CSV format:a header row with a comment column and (optionally) a label
column holding the hand-labelled ground truth (BUG/STYLE/PERFORMANCE/
SECURITY/PRAISE).When the label column exists an accuracy report is
printed too.
"""

import argparse
import csv
import re
import sys
from collections import OrderedDict

# 1. Category regexes
#    Each entry is (readable name, regex).  All are compiled case-insensitive.
#    \b = word boundary, so "bug" does NOT match inside "debug".

CATEGORIES = ["SECURITY", "BUG", "PERFORMANCE", "STYLE", "PRAISE"]  # = priority order

PATTERNS = OrderedDict()

PATTERNS["BUG"] = [
    ("crash",            r"\bcrash(?:es|ed|ing)?\b"),
    ("null/none check",  r"\b(?:(?:null|none|nil)[\s-]*(?:checks?|deref\w*|pointers?|references?)|null|nullptr|npe|nullpointerexception|nil)\b"),
    ("exception",        r"\b(?:exceptions?|throws?|thrown|stack\s*trace|traceback)\b"),
    ("empty/edge input", r"\b(?:empty|out[\s-]of[\s-]bounds|index\s*error|off[\s-]by[\s-]one|edge\s+cases?|corner\s+cases?)\b"),
    ("wrong/broken",     r"\b(?:bugs?|buggy|broken|incorrect(?:ly)?|wrong(?:ly)?|fails?|failing|failed|failure)\b|\b(?:throws?|raises?|returns?|gives?|causes?|shows?)\s+an?\s+(?:\w+\s+)?errors?\b"),
    ("does not work",    r"\b(?:does(?:n'?t|\s+not)|do(?:n'?t|\s+not)|will\s+not|won'?t|never)\s+(?:work|compile|run|handle|return|terminate|get\s+called)\b"),
    ("loop/concurrency", r"\b(?:infinite\s+loop|race\s+condition|deadlock|dead[\s-]lock|data\s+race|stack\s+overflow)\b"),
    ("overflow/divide",  r"\b(?:integer\s+overflow|division\s+by\s+zero|divide\s+by\s+zero|zerodivision\w*|underflow)\b"),
    ("regression/blocks", r"\b(?:regress(?:ion|es)?(?![\s-]*tests?)|breaks?\s+(?:when|if|on|the)|unhandled|uninitiali[sz]ed|prevents?\s+(?:\w+\s+){1,3}from|would\s+(?:still|skip|fail|break|crash|collide)|collisions?|out[\s-]of[\s-]range|useless)\b"),
]

PATTERNS["STYLE"] = [
    ("naming",           r"\b(?:renam\w*|naming|(?:variable|function|method|class|parameter|param)\s+names?|names?\s+(?:is|are|isn'?t))\b"),
    ("unclear/confusing",r"\b(?:unclear|confusing|cryptic|ambiguous|misleading|vague|hard\s+to\s+(?:read|follow|understand|parse))\b"),
    ("formatting",       r"\b(?:format(?:ting|ted)?|indent(?:ation|ed)?|whitespace|trailing\s+spaces?|line\s+length|blank\s+lines?|pep\s?-?8|camel\s?case|snake[\s_]case|lint(?:er|ing)?|prettier|black)\b"),
    ("readability",      r"\b(?:readab(?:le|ility)|maintainab(?:le|ility)|refactor\w*|simplif(?:y|ied|ication)|clean[\s-]?up|tidy)\b"),
    ("docs/comments",    r"\b(?:docstrings?|javadoc|documentation|(?:add|missing|needs?)\s+(?:a\s+)?(?:code\s+)?comments?|typos?|spelling)\b"),
    ("scope/stale",        r"\b(?:unrelated|stale|outdated|out[\s-]of[\s-]date|remove\s+(?:this|the)\s+(?:added|extra|unused|redundant)\s+\w+|revert(?:ed)?\s+(?:this|the))\b"),
    ("code smell",       r"\b(?:magic\s+numbers?|dead\s+code|unused\s+(?:import|variable|var|code|function|param\w*)s?|duplicat(?:e|ed|ion)\s+(?:code|logic)|nit(?:pick)?|convention|idiomatic|boilerplate)\b"),
]

PATTERNS["PERFORMANCE"] = [
    # Big-O: O(n^2), O(n²), O(n**2), O(2^n), O(n!)
    ("big-O",            r"(?-i:\bO\(\s*(?:n\s*(?:\^\s*\d|²|\*\*\s*\d)|2\s*\^\s*n|n!|n\s*log\s*n))"),
    ("slow/latency",     r"\b(?:slow(?:er|est|ly|s|down)?|sluggish|laggy|lag|latency|bottleneck|takes?\s+(?:forever|too\s+long)|hangs?)\b"),
    ("performance",      r"\b(?:performance|perf|inefficien\w*|efficien(?:t|cy)|optimi[sz]\w*|speed(?:\s*up)?|faster|throughput|overhead|expensive)\b"),
    ("memory",           r"\b(?:memory|leak(?:s|ing|ed)?|allocat\w*|garbage\s+collect\w*|heap|ram|footprint)\b"),
    ("caching/batching", r"\b(?:cach(?:e|ed|ing)|memoi[sz]\w*|batch(?:ing)?|lazy(?:\s+load\w*)?|vectori[sz]\w*|pre-?comput\w*|index(?:ing)?\s+the)\b"),
    ("loops/scale",      r"\b(?:nested\s+loops?|quadratic|exponential|n\+1|large\s+(?:data\s?sets?|inputs?|lists?|files?|arrays?|tables?)|big\s+data|millions?\s+of|scal(?:e|es|ing|ability))\b"),
    ("wasted work",      r"\b(?:unnecessar(?:y|ily)|redundant(?:ly)?|repeated(?:ly)?|re-?comput\w*|every\s+(?:iteration|call|time|request)|extra\s+(?:copy|copies|loop|pass|call)|(?:shallow|deep)\s+cop(?:y|ies)|copied\s+before)\b"),
]

PATTERNS["SECURITY"] = [
    ("injection/xss",    r"\b(?:sql\s*injection|command\s+injection|code\s+injection|injection|xss|cross[\s-]site|csrf|ssrf|rce|path\s+traversal|directory\s+traversal)\b"),
    ("vulnerability",    r"\b(?:vulnerab\w*|exploit\w*|insecure|unsafe|security|secure|cve-\d+-\d+|attack(?:er|ers|s)?|malicious|leaks?\s+(?:the\s+)?(?:data|info\w*|secrets?|credentials?))\b"),
    ("secrets",          r"\b(?:hard-?coded|plain[\s-]?text)\b|\b(?:passwords?|secrets?|api[\s_-]?keys?|credentials?|private\s+keys?)\b"),
    ("input validation", r"\b(?:sanitiz\w*|sanitis\w*|unvalidated|unsanitiz\w*|untrusted|user[\s-]supplied|user\s+input|validate\s+(?:the\s+)?input|escap(?:e|ed|ing)\s+(?:the\s+)?(?:input|user|html|query|string))\b"),
    ("auth/crypto",      r"\b(?:authenticat\w*|authori[sz]\w*|privilege\s+escalation|auth\s+bypass|encrypt\w*|decrypt\w*|md5|sha-?1|weak\s+(?:hash|crypto\w*|cipher)|hash(?:ed|ing)?\s+(?:the\s+)?passwords?)\b"),
    ("memory safety",    r"\b(?:buffer\s+overflow|use[\s-]after[\s-]free|format\s+string|eval\(|exec\(|unpickl\w*|pickle\.loads?|deserializ\w*|arbitrary\s+code(?:\s+execution)?|code\s+execution|ddos|denial[\s-]of[\s-]service)"),
]

PATTERNS["PRAISE"] = [
    ("positive adjective", r"\b(?:nice|great|good|excellent|awesome|amazing|fantastic|brilliant|beautiful|wonderful|perfect|superb|impressive|neat|lovely|solid|sweet|useful|helpful|valuable|improvements?|good\s+sign)\b"),
    ("well done",          r"\b(?:well\s+(?:done|written|thought|structured|organi[sz]ed)|nicely\s+done|kudos|bravo|props)\b"),
    ("approval",           r"\b(?:lgtm|looks\s+(?:good|great|fine)|ship\s+it|approved?|\+1)\b|👍|🎉|💯"),
    ("gratitude",          r"\b(?:thanks?|thank\s+you|appreciate[ds]?|grateful|cheers)\b"),
    ("love/like",          r"\b(?:i\s+(?:really\s+)?(?:love|like|enjoy)\s+(?:this|it|how|the)|love\s+(?:this|it|the|that)|a\s+pleasure|happy\s+with)\b"),
    ("clean/elegant",      r"\b(?:clean|clever|elegant|simple|tidy|readable)\s+(?:solution|approach|fix|implementation|code|work|design|way|idea)\b"),
]

# Compile everything once (case-insensitive; the big-O pattern turns that off
# for itself with the scoped flag (?-i:...)).
COMPILED = OrderedDict(
    (cat, [(name, re.compile(rx, re.IGNORECASE)) for name, rx in pats])
    for cat, pats in PATTERNS.items()
)

def build_combined_nfa():
    """Union of ALL category patterns -> one big machine.

    Every alternative sits inside a named group, e.g. (?P<BUG_3>...), so the
    group that fires tells us which category's pattern matched.
    """
    alts = []
    for cat, pats in PATTERNS.items():
        for i, (_, rx) in enumerate(pats):
            alts.append(f"(?P<{cat}_{i}>{rx})")
    return re.compile("|".join(alts), re.IGNORECASE)

COMBINED_NFA = build_combined_nfa()

# 2. Classifier

def find_matches(comment):
    """Return {category: [matched strings]} (one entry per matching pattern)."""
    found = OrderedDict()
    for cat, pats in COMPILED.items():
        hits = []
        for _name, rx in pats:
            m = rx.search(comment)
            if m:
                hits.append(m.group(0).strip())
        if hits:
            found[cat] = hits
    return found


def classify(comment):
    """Return (label, matched_strings, all_matches).

    Rule 2: most matched patterns wins.
    Rule 1: priority breaks ties  (SECURITY > BUG > PERFORMANCE > STYLE > PRAISE).
    """
    if not COMBINED_NFA.search(comment):          # machine never reaches an accepting state
        return "UNKNOWN", [], {}
    found = find_matches(comment)
    best = max(len(v) for v in found.values())
    tied = [c for c in CATEGORIES if c in found and len(found[c]) == best]
    label = tied[0]                                # CATEGORIES is already in priority order
    return label, found[label], found

# 3. CSV + reporting

def read_comments(path, comment_col, label_col):
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter='\t')
        if comment_col not in (reader.fieldnames or []):
            sys.exit(f"Column '{comment_col}' not found. Columns: {reader.fieldnames}")
        has_labels = label_col in reader.fieldnames
        rows = []
        for r in reader:
            text = (r.get(comment_col) or "").strip()
            if text:
                gold = (r.get(label_col) or "").strip().upper() if has_labels else None
                rows.append((text, gold))
    return rows, has_labels

def accuracy_report(gold, pred, show_matrix=True):
    labels = ["BUG", "STYLE", "PERFORMANCE", "SECURITY", "PRAISE", "UNKNOWN"]
    total = len(gold)
    correct = sum(g == p for g, p in zip(gold, pred))

    print("\n" + "=" * 62)
    print("ACCURACY REPORT")
    print("=" * 62)
    print(f"Overall accuracy: {correct}/{total} = {correct / total:.1%}\n")
    print(f"{'Category':<13}{'Precision':>10}{'Recall':>9}{'F1':>8}{'Support':>9}")
    print("-" * 49)
    for c in labels[:5]:
        tp = sum(g == c and p == c for g, p in zip(gold, pred))
        fp = sum(g != c and p == c for g, p in zip(gold, pred))
        fn = sum(g == c and p != c for g, p in zip(gold, pred))
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        print(f"{c:<13}{prec:>10.2f}{rec:>9.2f}{f1:>8.2f}{tp + fn:>9}")

    if show_matrix:
        print("\nCONFUSION MATRIX (rows = actual, columns = predicted)")
        w = 12
        print(" " * w + "".join(f"{c[:10]:>{w}}" for c in labels))
        for g in labels[:5]:
            row = [sum(gg == g and pp == p for gg, pp in zip(gold, pred)) for p in labels]
            print(f"{g:<{w}}" + "".join(f"{n:>{w}}" for n in row))

def main():
    ap = argparse.ArgumentParser(description="Regex/NFA code review comment classifier")
    ap.add_argument("csv_file", help="CSV file of review comments")
    ap.add_argument("--comment-col", default="comment", help="name of comment column (default: comment)")
    ap.add_argument("--label-col", default="label", help="name of ground-truth column (default: label)")
    ap.add_argument("--no-matrix", action="store_true", help="skip the confusion matrix")
    args = ap.parse_args()

    rows, has_labels = read_comments(args.csv_file, args.comment_col, args.label_col)
    if not rows:
        sys.exit("No comments found in the CSV.")

    gold, pred = [], []
    for i, (text, truth) in enumerate(rows, 1):
        label, matched, _ = classify(text)
        shown = ", ".join(repr(m) for m in matched) if matched else "no pattern matched"
        mark = ""
        if has_labels:
            mark = "  [OK]" if label == truth else f"  [WRONG - expected {truth}]"
            gold.append(truth)
        pred.append(label)
        print(f"Comment {i} -> {label} (matched: {shown}){mark}")

    if has_labels:
        accuracy_report(gold, pred, show_matrix=not args.no_matrix)


if __name__ == "__main__":
    main()
