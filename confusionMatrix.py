import numpy as np
import matplotlib.pyplot as plt

# Confusion matrices from your tables:
# Format: [[TP, FN],
#          [FP, TN]]
dvwa_cm = np.array([
    [4, 1],
    [1, 31]
])

juice_cm = np.array([
    [3, 1],
    [2, 174]
])

def plot_confusion_matrix(cm, title, save_path):
    fig, ax = plt.subplots(figsize=(6, 4))
    im = ax.imshow(cm)  # default colormap (no manual colors)

    # Tick labels
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted Vulnerable", "Predicted Secure"])
    ax.set_yticklabels(["Actual Vulnerable", "Actual Secure"])

    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("Actual Label")
    ax.set_title(title)

    # Annotate each cell with its value
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center")

    # Color bar
    fig.colorbar(im, ax=ax)
    plt.tight_layout()

    # Save
    plt.savefig(save_path, dpi=300)
    plt.close(fig)

# Generate both heatmaps
plot_confusion_matrix(dvwa_cm, "Confusion Matrix Heatmap (DVWA)", "confusion_matrix_dvwa.png")
plot_confusion_matrix(juice_cm, "Confusion Matrix Heatmap (OWASP Juice Shop)", "confusion_matrix_juice_shop.png")

print("Saved: confusion_matrix_dvwa.png")
print("Saved: confusion_matrix_juice_shop.png")
