import argparse, json, os, time
from fuzzer import StatefulFuzzer

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    fz = StatefulFuzzer(seed=args.seed)
    t0 = time.time()
    for _ in range(args.trials):
        fz.run_trial()
    dt = time.time() - t0

    os.makedirs("results", exist_ok=True)
    with open("results/summary.json", "w") as f:
        json.dump({**fz.summary(), "seconds": dt}, f, indent=2)
    with open("results/anomalies.jsonl", "w") as f:
        for a in fz.anomalies:
            f.write(json.dumps(a) + "\n")

    print("\n=== FUZZ SUMMARY ===")
    print(json.dumps({**fz.summary(), "seconds": dt}, indent=2))
    print("\nAnomalies saved to results/anomalies.jsonl (if any).\n")

if __name__ == "__main__":
    main()
