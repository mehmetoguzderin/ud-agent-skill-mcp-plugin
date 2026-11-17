"""Failure analysis for QSLM loop runs: stage heatmaps, failure loci, token budgets.

Usage: python loop_analysis.py --output DIR RUN_DIR [RUN_DIR ...]
Reads run.json/episodes written by evals/local/loop.mjs. Never loads a model.
Needs matplotlib and numpy (present in the local model environment).
SPDX-License-Identifier: MIT
"""
import argparse
import json
import math
from pathlib import Path


def wilson(passed, total, z=1.96):
    if not total:
        return (0.0, 0.0)
    p = passed / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return (max(0.0, centre - half), min(1.0, centre + half))


def sign_test(b, c):
    """Exact two-sided binomial test on discordant pairs (McNemar exact)."""
    n = b + c
    if not n:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


ADVISORY = {"skill_activated"}


def task_passed(row):
    """Outcome without the skill-uptake stage; recomputed so older runs compare identically."""
    return all(stage["passed"] or stage["name"] in ADVISORY for stage in row["stages"])


def load(run_dir):
    run_dir = Path(run_dir)
    run = json.loads((run_dir / "run.json").read_text())
    episodes = {}
    for file in sorted((run_dir / "episodes").glob("*.json")):
        value = json.loads(file.read_text())
        episodes[value["row"]["id"]] = value
    return run, episodes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("runs", nargs="+")
    args = parser.parse_args()
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    loaded = [load(item) for item in args.runs]
    labels = [run["label"] for run, _ in loaded]
    group = loaded[0][0]["group"]
    harnesses = list(dict.fromkeys(h for run, _ in loaded for h in run["harnesses"]))
    scenarios = list(dict.fromkeys(s for run, _ in loaded for s in run["scenarios"]))
    summary = {"group": group, "runs": [], "paired": None, "figures": []}

    # 1. Stage x episode heatmap per run (green pass, red fail, black marker = first failure).
    fig, axes = plt.subplots(1, len(loaded), figsize=(6.5 * len(loaded), 7.5), squeeze=False)
    for axis, (run, episodes) in zip(axes[0], loaded):
        rows = [episodes[key]["row"] for key in sorted(episodes, key=lambda k: (episodes[k]["row"]["scenario_id"], episodes[k]["row"]["harness"], episodes[k]["row"]["seed"]))]
        stage_names = list(dict.fromkeys(stage["name"] for row in rows for stage in row["stages"]))
        matrix = np.full((len(stage_names), len(rows)), np.nan)
        for j, row in enumerate(rows):
            for stage in row["stages"]:
                matrix[stage_names.index(stage["name"]), j] = 1.0 if stage["passed"] else 0.0
        cmap = matplotlib.colors.ListedColormap(["#d9534f", "#5cb85c"])
        cmap.set_bad("#dddddd")
        axis.imshow(np.ma.masked_invalid(matrix), cmap=cmap, vmin=0, vmax=1, aspect="auto")
        for j, row in enumerate(rows):
            if row["first_failure"] in stage_names:
                axis.plot(j, stage_names.index(row["first_failure"]), marker="x", color="black", markersize=8)
        axis.set_yticks(range(len(stage_names)), stage_names, fontsize=8)
        axis.set_xticks(range(len(rows)), [f'{r["scenario_id"]}/{r["harness"]}/{r["seed"]}' for r in rows], rotation=90, fontsize=7)
        axis.set_title(f'{group} {run["label"]}: {sum(r["passed"] for r in rows)}/{len(rows)} passed (x = first failure)', fontsize=10)
    fig.text(0.01, 0.005, "grey = stage not applicable to the scenario", fontsize=7, va="bottom")
    fig.tight_layout(rect=(0, 0.02, 1, 1))
    name = f"{group}-stage-heatmap.png"
    fig.savefig(out / name, dpi=130)
    plt.close(fig)
    summary["figures"].append(name)

    # 2. Pass rate harness x scenario, one panel per run.
    fig, axes = plt.subplots(1, len(loaded), figsize=(4.5 * len(loaded), 3.2), squeeze=False)
    for axis, (run, episodes) in zip(axes[0], loaded):
        rates = np.full((len(harnesses), len(scenarios)), np.nan)
        for i, h in enumerate(harnesses):
            for j, s in enumerate(scenarios):
                rows = [e["row"] for e in episodes.values() if e["row"]["harness"] == h and e["row"]["scenario_id"] == s]
                if rows:
                    rates[i, j] = sum(r["passed"] for r in rows) / len(rows)
                    axis.text(j, i, f'{sum(r["passed"] for r in rows)}/{len(rows)}', ha="center", va="center", fontsize=10)
        axis.imshow(rates, cmap="RdYlGn", vmin=0, vmax=1)
        axis.set_xticks(range(len(scenarios)), scenarios)
        axis.set_yticks(range(len(harnesses)), harnesses)
        axis.set_title(f'{run["label"]} pass rate', fontsize=10)
    fig.tight_layout()
    name = f"{group}-harness-scenario-heatmap.png"
    fig.savefig(out / name, dpi=130)
    plt.close(fig)
    summary["figures"].append(name)

    # 3. First-failure locus counts (stage x harness) per run.
    loci = list(dict.fromkeys(e["row"]["first_failure"] or "passed" for _, eps in loaded for e in eps.values()))
    fig, axes = plt.subplots(1, len(loaded), figsize=(4.5 * len(loaded), 0.45 * len(loci) + 1.8), squeeze=False)
    for axis, (run, episodes) in zip(axes[0], loaded):
        counts = np.zeros((len(loci), len(harnesses)))
        for e in episodes.values():
            counts[loci.index(e["row"]["first_failure"] or "passed"), harnesses.index(e["row"]["harness"])] += 1
        axis.imshow(counts, cmap="Reds", vmin=0, vmax=max(1, counts.max()))
        for i in range(len(loci)):
            for j in range(len(harnesses)):
                if counts[i, j]:
                    axis.text(j, i, int(counts[i, j]), ha="center", va="center", color="white" if counts[i, j] > counts.max() / 2 else "black")
        axis.set_yticks(range(len(loci)), loci, fontsize=8)
        axis.set_xticks(range(len(harnesses)), harnesses, fontsize=8)
        axis.set_title(f'{run["label"]}: first failure locus', fontsize=10)
    fig.tight_layout()
    name = f"{group}-first-failure-heatmap.png"
    fig.savefig(out / name, dpi=130)
    plt.close(fig)
    summary["figures"].append(name)

    # 4. Prompt-token budget per request index (does the request fit the 32k window?).
    fig, axis = plt.subplots(figsize=(7, 3.6))
    for (run, episodes), marker in zip(loaded, "os^v"):
        for h in harnesses:
            points = [(i, t) for e in episodes.values() if e["row"]["harness"] == h for i, t in enumerate(e["row"]["prompt_tokens"]) if t]
            if points:
                xs, ys = zip(*points)
                axis.scatter(np.array(xs) + 0.1 * harnesses.index(h), ys, marker=marker, alpha=0.6, label=f'{run["label"]}/{h}')
    axis.axhline(loaded[0][0]["limits"]["context"], color="black", linestyle="--", linewidth=1, label="context 32,768")
    axis.set_yscale("log")
    axis.set_xlabel("request index within episode")
    axis.set_ylabel("prompt tokens (MiniCPM tokenizer)")
    axis.legend(fontsize=6, ncol=2)
    fig.tight_layout()
    name = f"{group}-token-budget.png"
    fig.savefig(out / name, dpi=130)
    plt.close(fig)
    summary["figures"].append(name)

    for run, episodes in loaded:
        rows = [e["row"] for e in episodes.values()]
        passed = sum(r["passed"] for r in rows)
        task = sum(task_passed(r) for r in rows)
        per = {}
        for h in harnesses:
            for s in scenarios:
                sel = [r for r in rows if r["harness"] == h and r["scenario_id"] == s]
                if sel:
                    per[f"{h}/{s}"] = {"passed": sum(r["passed"] for r in sel), "total": len(sel),
                                       "mean_requests": round(sum(r["requests"] for r in sel) / len(sel), 2),
                                       "max_prompt_tokens": max((max(r["prompt_tokens"] or [0]) for r in sel), default=0),
                                       "first_failures": sorted({r["first_failure"] or "passed" for r in sel})}
        stage_pass = {}
        for r in rows:
            for stage in r["stages"]:
                cell = stage_pass.setdefault(stage["name"], [0, 0])
                cell[0] += stage["passed"]
                cell[1] += 1
        summary["runs"].append({"label": run["label"], "episodes": len(rows), "passed": passed, "pass_rate": round(passed / max(1, len(rows)), 3), "task_passed": task, "task_wilson95": [round(v, 3) for v in wilson(task, len(rows))],
                                "wilson95": [round(v, 3) for v in wilson(passed, len(rows))],
                                "mean_requests_passing": round(sum(r["requests"] for r in rows if r["passed"]) / max(1, passed), 2) if passed else None,
                                "stage_pass": {k: f"{v[0]}/{v[1]}" for k, v in stage_pass.items()}, "cells": per,
                                "completion_tokens": sum(r["completion_tokens"] for r in rows), "wall_s": round(sum(r["elapsed_ms"] for r in rows) / 1000, 1)})
    if len(loaded) >= 2:
        (_, first), (_, last) = loaded[0], loaded[-1]
        keys = sorted(set(first) & set(last))
        b = sum(1 for k in keys if not first[k]["row"]["passed"] and last[k]["row"]["passed"])
        c = sum(1 for k in keys if first[k]["row"]["passed"] and not last[k]["row"]["passed"])
        advanced = sum(1 for k in keys if not last[k]["row"]["passed"] and not first[k]["row"]["passed"] and
                       [s["name"] for s in last[k]["row"]["stages"]].index(last[k]["row"]["first_failure"]) >
                       [s["name"] for s in first[k]["row"]["stages"]].index(first[k]["row"]["first_failure"]))
        tb = sum(1 for k in keys if not task_passed(first[k]["row"]) and task_passed(last[k]["row"]))
        tc = sum(1 for k in keys if task_passed(first[k]["row"]) and not task_passed(last[k]["row"]))
        summary["paired"] = {"pairs": len(keys), "fixed": b, "regressed": c, "both_failed_but_advanced": advanced, "mcnemar_exact_p": round(sign_test(b, c), 4),
                             "task_fixed": tb, "task_regressed": tc, "task_mcnemar_exact_p": round(sign_test(tb, tc), 4)}
    lines = [f"# {group} QSLM loop analysis", "", "| Run | Passed (strict) | Wilson 95% | Task outcome (skill read not required) | Wilson 95% | Mean requests (passing) | Completion tokens | Wall s |", "|---|---:|---|---:|---|---:|---:|---:|"]
    for item in summary["runs"]:
        lines.append(f'| {item["label"]} | {item["passed"]}/{item["episodes"]} | {item["wilson95"]} | {item["task_passed"]}/{item["episodes"]} | {item["task_wilson95"]} | {item["mean_requests_passing"]} | {item["completion_tokens"]} | {item["wall_s"]} |')
    for item in summary["runs"]:
        lines += ["", f'## {item["label"]}: cells', "", "| Harness/scenario | Passed | Mean requests | Max prompt tokens | First failures |", "|---|---:|---:|---:|---|"]
        for key, cell in item["cells"].items():
            lines.append(f'| {key} | {cell["passed"]}/{cell["total"]} | {cell["mean_requests"]} | {cell["max_prompt_tokens"]} | {", ".join(cell["first_failures"])} |')
        lines += ["", "Stage pass counts: " + ", ".join(f"{k} {v}" for k, v in item["stage_pass"].items())]
    if summary["paired"]:
        lines += ["", f'Paired (same scenario/harness/seed): {json.dumps(summary["paired"])}']
    lines += ["", "Figures: " + ", ".join(summary["figures"])]
    (out / f"{group}-summary.md").write_text("\n".join(lines) + "\n")
    (out / f"{group}-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"output": str(out), "figures": summary["figures"], "runs": [{k: r[k] for k in ("label", "passed", "episodes")} for r in summary["runs"]], "paired": summary["paired"]}))


if __name__ == "__main__":
    main()
