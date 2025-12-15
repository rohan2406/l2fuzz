# make_plots.py
# Usage:
#   pip install matplotlib
#   python make_plots.py --results_dir results

import argparse, os, json, collections
import matplotlib.pyplot as plt

def load_json(path):
    with open(path) as f:
        return json.load(f)

def load_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def bar_chart(labels, values, title, xlabel, ylabel, out_path, rotation=25):
    plt.figure()
    x = range(len(labels))
    plt.bar(x, values)
    plt.xticks(list(x), labels, rotation=rotation, ha="right")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def line_chart(xs, ys, title, xlabel, ylabel, out_path):
    plt.figure()
    plt.plot(xs, ys)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results_dir", default="results")
    args = ap.parse_args()

    metrics_path = os.path.join(args.results_dir, "metrics.json")
    anomalies_path = os.path.join(args.results_dir, "anomalies.jsonl")
    summary_path = os.path.join(args.results_dir, "summary.json")
    timeline_path = os.path.join(args.results_dir, "timeline.jsonl")

    if not os.path.exists(metrics_path):
        raise SystemExit(f"Missing {metrics_path}. Run make_metrics.py first.")
    if not os.path.exists(anomalies_path):
        raise SystemExit(f"Missing {anomalies_path}. Run your fuzzer first.")

    metrics = load_json(metrics_path)
    anomalies = load_jsonl(anomalies_path)

    # -------- Bar: Top anomaly reasons --------
    reasons = collections.Counter()
    for a in anomalies:
        r = (a.get("reason") or "").split(":")[0].strip()
        if r:
            reasons[r] += 1
    top = reasons.most_common(12)
    labels = [k for k, _ in top]
    values = [v for _, v in top]
    out = os.path.join(args.results_dir, "anomaly_reasons.png")
    bar_chart(labels, values, "Top Anomaly Reasons", "Reason", "Count", out)

    # -------- Bar: Opcode frequency within anomalies --------
    op_counts = collections.Counter()
    for a in anomalies:
        hexp = a.get("minimized_payload_hex") or a.get("original_payload_hex") or ""
        try:
            b = bytes.fromhex(hexp)
            if b:
                op_counts[b[0]] += 1
        except Exception:
            pass
    # map opcode → name
    def op_name(op):
        return {1:"CR",2:"CP",3:"FR",4:"FP",5:"DT",6:"DC"}.get(op, f"0x{op:02x}")
    ops_sorted = op_counts.most_common()
    labels = [f"{op_name(k)}" for k, _ in ops_sorted]
    values = [v for _, v in ops_sorted]
    out = os.path.join(args.results_dir, "opcode_counts.png")
    bar_chart(labels, values, "Opcode Frequency in Anomalies", "Opcode", "Count", out, rotation=0)

    # -------- Optional: time-series from timeline.jsonl --------
    if os.path.exists(timeline_path):
        tl = load_jsonl(timeline_path)

        # cumulative anomalies over time
        xs = []
        ys = []
        count = 0
        for row in tl:
            xs.append(row.get("trial", 0))
            if row.get("event") in ("Anomaly", "Rejected"):  # rejected are parse/runtime; keep if you like
                count += 1 if row.get("event") == "Anomaly" else 0
            ys.append(count)
        if xs:
            out = os.path.join(args.results_dir, "cumulative_anomalies_over_time.png")
            line_chart(xs, ys, "Cumulative Protocol Anomalies Over Time", "Trial", "Anomalies", out)

        # cumulative unique states over time
        seen_states = set()
        xs, ys = [], []
        for row in tl:
            xs.append(row.get("trial", 0))
            st = row.get("state_after")
            if st:
                seen_states.add(st)
            ys.append(len(seen_states))
        if xs:
            out = os.path.join(args.results_dir, "cumulative_states_over_time.png")
            line_chart(xs, ys, "Cumulative Unique States Over Time", "Trial", "States", out)

        # cumulative unique transitions over time
        seen_trans = set()
        xs, ys = [], []
        for row in tl:
            xs.append(row.get("trial", 0))
            tr = row.get("transition")
            if tr:
                seen_trans.add(tuple(tr))
            ys.append(len(seen_trans))
        if xs:
            out = os.path.join(args.results_dir, "cumulative_transitions_over_time.png")
            line_chart(xs, ys, "Cumulative Unique Transitions Over Time", "Trial", "Transitions", out)

    print("Charts written to:", args.results_dir)

if __name__ == "__main__":
    main()
