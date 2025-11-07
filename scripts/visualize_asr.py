import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import argparse, os, re
import numpy as np

sns.set_theme(style="whitegrid")

# --- CLI args ---
p = argparse.ArgumentParser()
p.add_argument("--infile", default="outputs/asr_report.csv")
p.add_argument("--outdir", default="outputs/plots")
args = p.parse_args()

os.makedirs(args.outdir, exist_ok=True)

# --- Load data ---
df = pd.read_csv(args.infile)
df["ASR"] = df["ASR"].astype(float)

# Try to infer attack class if not present
def infer_class(aid):
    if re.match(r"^I\d", str(aid)): return "indirect"
    if re.match(r"^D\d", str(aid)): return "direct"
    return "unknown"

if "attack_class" not in df.columns:
    df["attack_class"] = df["attack_id"].apply(infer_class)

# --- Aggregate summary ---
summary = (
    df.groupby(["model","condition","attack_class"])
      .agg(mean_ASR=("ASR","mean"), std_ASR=("ASR","std"), n=("ASR","count"))
      .reset_index()
)

print("\n=== Aggregate Summary by Model × Condition × Class ===\n")
print(summary.round(3))
summary.to_csv(f"{args.outdir}/aggregate_summary.csv", index=False)

# --- Overall Heatmap ---
pivot = df.pivot_table(index="attack_id", columns="model", values="ASR", aggfunc="mean")
plt.figure(figsize=(10,8))
sns.heatmap(pivot, annot=True, fmt=".2f", cmap="Reds", cbar_kws={'label':'ASR'})
plt.title("Attack Success Rate (ASR) per Attack ID and Model")
plt.ylabel("Attack ID")
plt.xlabel("Model")
plt.tight_layout()
plt.savefig(f"{args.outdir}/01_heatmap_asr_models.png", dpi=300)
plt.close()

# --- ASR by Attack Class (Direct vs Indirect) ---
plt.figure(figsize=(8,5))
sns.barplot(data=df, x="attack_class", y="ASR", hue="model", errorbar="sd", capsize=0.1)
plt.title("Average ASR by Attack Class and Model")
plt.ylabel("Mean ASR ± SD")
plt.xlabel("Attack Class")
plt.tight_layout()
plt.savefig(f"{args.outdir}/02_bar_asr_by_class.png", dpi=300)
plt.close()

# --- Per-Condition Comparison (faceted bar plot) ---
plt.figure(figsize=(12,6))
sns.barplot(data=df, x="attack_id", y="ASR", hue="condition", errorbar=None)
plt.xticks(rotation=90)
plt.title("ASR by Attack and Condition")
plt.ylabel("Attack Success Rate (ASR)")
plt.xlabel("Attack ID")
plt.tight_layout()
plt.savefig(f"{args.outdir}/03_bar_asr_condition.png", dpi=300)
plt.close()

# --- Distribution per Model (Box plot) ---
plt.figure(figsize=(8,5))
sns.boxplot(data=df, x="model", y="ASR", hue="attack_class")
plt.title("Distribution of ASR per Model and Attack Class")
plt.tight_layout()
plt.savefig(f"{args.outdir}/04_box_asr_model_class.png", dpi=300)
plt.close()

# --- Class-wise means (for thesis figure) ---
plt.figure(figsize=(10,6))

# Map linestyles manually per model
linestyle_map = {"gemma3:1b": "-", "gemma3:latest": "--", "llama3:latest": ":"}
palette = sns.color_palette("Set2")

for i, (model, subset) in enumerate(summary.groupby("model")):
    sns.pointplot(
        data=subset,
        x="condition",
        y="mean_ASR",
        hue="attack_class",
        markers="o",
        linestyles=linestyle_map.get(model, "-"),
        capsize=0.1,
        err_kws={"linewidth": 1},
        dodge=True,
        palette=palette,
        legend=False  # avoid Seaborn's internal legend stacking
    )
    # Add model label inline
    plt.text(
        x=len(subset["condition"].unique()) - 0.8,
        y=subset["mean_ASR"].mean(),
        s=model,
        fontsize=10,
        fontweight="bold"
    )

plt.title("Mean ASR by Condition and Attack Class")
plt.ylabel("Mean ASR ± SD")
plt.xlabel("Condition")
plt.legend(title="Attack Class", loc="upper left")
plt.tight_layout()
plt.savefig(f"{args.outdir}/05_point_mean_asr_condition_class.png", dpi=300)
plt.close()

# --- Export top-10 vulnerabilities ---
top = df.sort_values("ASR", ascending=False).head(10)
print("\n=== Top 10 Vulnerabilities ===\n")
print(top[["model","condition","attack_id","ASR"]])
top.to_csv(f"{args.outdir}/top10_vulnerabilities.csv", index=False)

print("\n✅ Saved all visualizations to:", args.outdir)
