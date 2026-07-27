import matplotlib.pyplot as plt
import numpy as np
import os

systems = ['Rathee et al.\n(Blockchain)', 'Song et al.\n(Block+ML)', 'Kumar et al.\n(Block+IDS)', 'Hussain et al.\n(Quantum)', 'NetGuard\n(HMAC)']

accuracy = [88.5, 93.2, 91.0, 94.5, 98.2]
precision = [85.0, 91.8, 89.5, 92.0, 97.5]

x = np.arange(len(systems))
width = 0.35

fig, ax = plt.subplots(figsize=(10, 6))
rects1 = ax.bar(x - width/2, accuracy, width, label='Accuracy (%)', color='#2196F3')
rects2 = ax.bar(x + width/2, precision, width, label='Precision (%)', color='#4CAF50')

ax.set_ylabel('Percentage (%)', fontsize=12)
ax.set_title('Efficiency Comparison: Literature Survey vs. NetGuard', fontsize=14, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(systems, fontsize=10)
ax.set_ylim([80, 105])
ax.legend()

ax.bar_label(rects1, padding=3, fmt='%.1f%%')
ax.bar_label(rects2, padding=3, fmt='%.1f%%')

fig.tight_layout()

output_path = r'c:\Users\varun\OneDrive\deskto\NETGRUARD\comparison_graph.png'
plt.savefig(output_path, dpi=300)
print(f"Graph successfully saved to {output_path}")
