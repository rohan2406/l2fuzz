# make_metrics.py
import argparse, json, os, collections

def load_summary(path):
    with open(path) as f:
        return json.load(f)

def load_anomalies(path):
    cases = []
    if not os.path.exists(path):
        return cases
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases

def opcode_name(op):
    mapping = {1:"CR",2:"CP",3:"FR",4:"FP",5:"DT",6:"DC"}
    return mapping.get(op, f"0x{op:02x}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results_dir", default="results")
    ap.add_argument("--out_dir", default="results")
    args = ap.parse_args()

    summ_path = os.path.join(args.results_dir, "summary.json")
    anom_path = os.path.join(args.results_dir, "anomalies.jsonl")
    summary = load_summary(summ_path)
    anomalies = load_anomalies(anom_path)

    trials    = summary.get("trials", 0)
    accepted  = summary.get("accepted", 0)
    rejected  = summary.get("rejected", 0)
    anom_cnt  = summary.get("anomalies", 0)
    seconds   = summary.get("seconds", None)

    accept_rate  = accepted / trials if trials else 0.0
    reject_rate  = rejected / trials if trials else 0.0
    anomaly_rate = anom_cnt / trials if trials else 0.0
    throughput   = trials / seconds if (seconds and seconds > 0) else None

    parser_err = 0
    proto_anom = 0
    reason_counter = collections.Counter()
    opcode_counter = collections.Counter()
    orig_lens, min_lens = [], []

    for a in anomalies:
        reason = a.get("reason","")
        reason_counter[reason.split(":")[0].strip()] += 1
        if reason.startswith("Parser/Runtime error"):
            parser_err += 1
        else:
            proto_anom += 1

        hexp = a.get("minimized_payload_hex") or a.get("original_payload_hex") or ""
        try:
            b = bytes.fromhex(hexp)
            if len(b) > 0:
                opcode_counter[b[0]] += 1
        except Exception:
            pass

        try:
            ohex = a.get("original_payload_hex","")
            mhex = a.get("minimized_payload_hex","")
            if ohex:
                orig_lens.append(len(bytes.fromhex(ohex)))
            if mhex:
                min_lens.append(len(bytes.fromhex(mhex)))
        except Exception:
            pass

    unique_minimized = len(set([
        a.get("minimized_payload_hex")
        for a in anomalies if a.get("minimized_payload_hex")
    ]))
    mean_orig = sum(orig_lens)/len(orig_lens) if orig_lens else 0.0
    mean_min  = sum(min_lens)/len(min_lens) if min_lens else 0.0
    reduction = (1 - (mean_min/mean_orig)) if mean_orig > 0 else 0.0

    metrics = {
        "trials": trials,
        "accepted": accepted,
        "rejected": rejected,
        "anomalies": anom_cnt,
        "accept_rate": round(accept_rate, 4),
        "reject_rate": round(reject_rate, 4),
        "anomaly_rate": round(anomaly_rate, 4),
        "seconds": seconds,
        "throughput_trials_per_sec": throughput,
        "states_visited": summary.get("visited_states", []),
        "transitions_visited": summary.get("visited_transitions", []),
        "parser_errors": parser_err,
        "protocol_anomalies": proto_anom,
        "unique_minimized_payloads": unique_minimized,
        "mean_original_payload_len": mean_orig,
        "mean_minimized_payload_len": mean_min,
        "avg_length_reduction_fraction": reduction,
        "top_reasons": reason_counter.most_common(10),
        "opcodes_in_anomalies": [
            {"opcode": k, "name": opcode_name(k), "count": v}
            for k, v in opcode_counter.most_common()
        ],
    }

    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    md = []
    md.append("# Fuzzing Metrics\n")
    md.append(f"- Trials: **{trials}**")
    md.append(f"- Accepted: **{accepted}** ({accept_rate:.2%})")
    md.append(f"- Rejected: **{rejected}** ({reject_rate:.2%})")
    md.append(f"- Anomalies: **{anom_cnt}** ({anomaly_rate:.2%})")
    if throughput:
        md.append(f"- Throughput: **{throughput:.1f} trials/sec**")
    md.append("")
    md.append(f"- Parser errors: **{parser_err}**")
    md.append(f"- Protocol anomalies: **{proto_anom}**")
    md.append(f"- Unique minimized payloads: **{unique_minimized}**")
    md.append(f"- Avg original payload length: **{mean_orig:.2f}**")
    md.append(f"- Avg minimized payload length: **{mean_min:.2f}** (reduction {reduction:.1%})")
    md.append("")
    md.append("## States & Transitions")
    md.append(f"- States visited: `{summary.get('visited_states', [])}`")
    md.append(f"- Transitions visited: `{summary.get('visited_transitions', [])}`")
    md.append("")
    md.append("## Top anomaly reasons")
    for k,v in metrics["top_reasons"]:
        md.append(f"- {k}: {v}")
    md.append("")
    md.append("## Opcodes in anomalies (by count)")
    for item in metrics["opcodes_in_anomalies"]:
        md.append(f"- {item['name']} (0x{item['opcode']:02x}): {item['count']}")
    with open(os.path.join(args.out_dir, "metrics.md"), "w") as f:
        f.write("\n".join(md))

    print("Wrote:", os.path.join(args.out_dir, "metrics.json"))
    print("Wrote:", os.path.join(args.out_dir, "metrics.md"))

if __name__ == "__main__":
    main()
