# plot_attack_summary.py
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import os # Import os for path manipulation

# Load CSV
df = pd.read_csv('packet_labels.csv')

# Count occurrences of each severity
severity_counts = Counter(df['severity']) # Note: 'severity' is lowercase in CSV header

# Ensure order: High, Medium, Low
severity_levels = ['High', 'Medium', 'Low']
counts = [severity_counts.get(level, 0) for level in severity_levels]

# Plot
plt.figure(figsize=(6, 4))
bars = plt.bar(severity_levels, counts, color=['red', '#FFA500', 'green']) # Use string for orange
plt.title('🚨 Attack Summary by Severity')
plt.xlabel('Severity')
plt.ylabel('Number of Alerts')
plt.grid(axis='y', linestyle='--', alpha=0.7)

# Annotate bars
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, height + 0.5, str(height), ha='center', va='bottom')

plt.tight_layout()

# Save the plot to the static directory for the web app
plot_dir = 'static'
os.makedirs(plot_dir, exist_ok=True) # Ensure static directory exists
plt.savefig(os.path.join(plot_dir, "attack_summary.png"))
# plt.show() # Remove or comment out plt.show() to prevent blocking