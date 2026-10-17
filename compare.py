import matplotlib.pyplot as plt
from classifier import classify, read_comments
import keyword_classifier

classifiers = ["Keyword Classifier", "Regex/NFA Classifier"]
rows, _ = read_comments("comments.csv", "comment", "label")
rows = [(t, g) for t, g in rows if g]          # only labelled comments
kw_ok = sum(keyword_classifier.classify(t) == g for t, g in rows)
rx_ok = sum(classify(t)[0] == g for t, g in rows)
accuracy = [100 * kw_ok / len(rows), 100 * rx_ok / len(rows)]

plt.figure(figsize=(8, 5))
bars = plt.bar(classifiers, accuracy)

plt.title("Keyword vs Regex/NFA Classifier")
plt.ylabel("Accuracy (%)")
plt.ylim(0, 100)

for bar, value in zip(bars, accuracy):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 1,
        f"{value:.1f}%",
        ha="center"
    )
print("CLASSIFIER COMPARISON")
print("---------------------")
print(f"Keyword Classifier Accuracy: {accuracy[0]}%")
print(f"Regex/NFA Classifier Accuracy: {accuracy[1]}%")
plt.tight_layout()
plt.savefig("comparison_graph.png")
plt.show()
