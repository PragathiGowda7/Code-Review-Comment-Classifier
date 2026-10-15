
import matplotlib.pyplot as plt

classifiers = ["Keyword Classifier", "Regex/NFA Classifier"]
accuracy = [69.0, 72.4]  # Update Regex after correcting for missing label

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
