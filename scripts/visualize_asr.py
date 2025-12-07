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

# Infer attack class (D = direct, I = indirect)
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

summary.to_csv(f"{args.outdir}/aggregate_summary.csv", index=False)
print("\nWrote: aggregate_summary.csv")


#   1) HEATMAP — FULL DATASET (average ASR per attack × model)
pivot = df.pivot_table(index="attack_id", columns="model", values="ASR", aggfunc="mean")

plt.figure(figsize=(11,9))
sns.heatmap(pivot, cmap="Reds", annot=False, cbar_kws={'label':'ASR'})
plt.title("ASR Heatmap (All Conditions Averaged)")
plt.ylabel("Attack ID")
plt.xlabel("Model")
plt.tight_layout()
plt.savefig(f"{args.outdir}/01_heatmap_asr_models.png", dpi=300)
plt.close()

#   1B) HEATMAP (C2-only — shows where real failures occur)
df_c2 = df[df["condition"] == "C2_secret_seeded"]
pivot_c2 = df_c2.pivot_table(index="attack_id", columns="model", values="ASR", aggfunc="mean")

plt.figure(figsize=(11,9))
sns.heatmap(pivot_c2, cmap="Reds", annot=False, cbar_kws={'label':'ASR'})
plt.title("ASR Heatmap — C2 Secret-Seeded Condition Only")
plt.ylabel("Attack ID")
plt.xlabel("Model")
plt.tight_layout()
plt.savefig(f"{args.outdir}/01B_heatmap_asr_c2_only.png", dpi=300)
plt.close()

#   2) ASR BY ATTACK CLASS (Direct vs Indirect)
plt.figure(figsize=(8,5))
sns.barplot(
    data=df,
    x="attack_class",
    y="ASR",
    hue="model",
    errorbar="sd",
    capsize=0.1
)
plt.title("Average ASR by Attack Class and Model")
plt.ylabel("Mean ASR ± SD")
plt.xlabel("Attack Class")
plt.tight_layout()
plt.savefig(f"{args.outdir}/02_bar_asr_by_class.png", dpi=300)
plt.close()

#   3) BOX PLOT — MODEL × ATTACK CLASS (clean distribution)
plt.figure(figsize=(8,5))
sns.boxplot(
    data=df,
    x="model",
    y="ASR",
    hue="attack_class"
)
plt.title("Distribution of ASR per Model × Attack Class")
plt.ylabel("ASR Distribution")
plt.xlabel("Model")
plt.tight_layout()
plt.savefig(f"{args.outdir}/03_box_asr_model_class.png", dpi=300)
plt.close()

#   4) POINT PLOT — CONDITION × CLASS × MODEL
plt.figure(figsize=(10,6))
linestyle_map = {"gemma3:1b": "-", "gemma3:latest": "--", "llama3:latest": ":"}
palette = sns.color_palette("Set2")

for model, subset in summary.groupby("model"):
    sns.pointplot(
        data=subset,
        x="condition",
        y="mean_ASR",
        hue="attack_class",
        markers="o",
        linestyles=linestyle_map.get(model, "-"),
        capsize=0.1,
        dodge=True,
        palette=palette,
        legend=False
    )
    plt.text(
        x=len(subset["condition"].unique()) - 0.8,
        y=subset["mean_ASR"].mean(),
        s=model,
        fontsize=9,
        fontweight="bold"
    )

plt.title("Mean ASR by Condition × Attack Class (per Model)")
plt.ylabel("Mean ASR ± SD")
plt.xlabel("Condition")
plt.legend(title="Attack Class")
plt.tight_layout()
plt.savefig(f"{args.outdir}/04_point_mean_asr_condition_class.png", dpi=300)
plt.close()

#   5) ASR DISTRIBUTION HISTOGRAM
plt.figure(figsize=(7,5))
sns.histplot(df["ASR"], bins=20)
plt.title("Histogram of ASR Values (All Models × Conditions)")
plt.xlabel("ASR")
plt.ylabel("Frequency")
plt.tight_layout()
plt.savefig(f"{args.outdir}/05_hist_asr_distribution.png", dpi=300)
plt.close()

#   6) TOP 10 WORST VULNERABILITIES (Global)
top = df.sort_values("ASR", ascending=False).head(10)
top.to_csv(f"{args.outdir}/top10_vulnerabilities.csv", index=False)

#   7) TOP 10 PER MODEL 
for model in df["model"].unique():
    subset = df[df["model"] == model].sort_values("ASR", ascending=False).head(10)
    subset.to_csv(f"{args.outdir}/top10_{model.replace(':','_')}.csv", index=False)

print("\n All clean, publication-grade plots saved to:", args.outdir)
