import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import argparse, os

# --- CLI args ---
p = argparse.ArgumentParser()
p.add_argument("--infile", default="outputs/asr_report.csv")
p.add_argument("--outdir", default="outputs/plots")
args = p.parse_args()

os.makedirs(args.outdir, exist_ok=True)

# --- Load data ---
df = pd.read_csv(args.infile)
df["ASR"] = df["ASR"].astype(float)

# --- Basic summary ---
print("Loaded:", len(df), "rows")
print(df.groupby("model")["ASR"].mean().round(3))

# --- Plot 1: overall heatmap ---
pivot = df.pivot_table(index="attack_id", columns="model", values="ASR", aggfunc="mean")
plt.figure(figsize=(10, 8))
sns.heatmap(pivot, annot=True, fmt=".2f", cmap="Reds", cbar_kws={'label': 'ASR'})
plt.title("Attack Success Rate (ASR) per Attack ID and Model")
plt.ylabel("Attack ID")
plt.xlabel("Model")
plt.tight_layout()
plt.savefig(f"{args.outdir}/heatmap_asr_models.png", dpi=300)
plt.close()

# --- Plot 2: per-condition barplot ---
plt.figure(figsize=(12, 6))
sns.barplot(data=df, x="attack_id", y="ASR", hue="condition", errorbar=None)
plt.xticks(rotation=90)
plt.title("ASR by Attack and Condition")
plt.ylabel("Attack Success Rate (ASR)")
plt.xlabel("Attack ID")
plt.tight_layout()
plt.savefig(f"{args.outdir}/bar_asr_condition.png", dpi=300)
plt.close()

# --- Plot 3: per-model distribution ---
plt.figure(figsize=(8, 5))
sns.boxplot(data=df, x="model", y="ASR")
plt.title("Distribution of ASR per Model")
plt.tight_layout()
plt.savefig(f"{args.outdir}/box_asr_model.png", dpi=300)
plt.close()

# --- Top 10 vulnerabilities ---
top = df.sort_values("ASR", ascending=False).head(10)
print("\nTop 10 vulnerabilities:\n", top[["model","condition","attack_id","ASR"]])
top.to_csv(f"{args.outdir}/top10_vulnerabilities.csv", index=False)

print("\nSaved visualizations to:", args.outdir)