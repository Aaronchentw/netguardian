"""NetGuardian: offline, standard-library-only network telemetry triage prototype."""
import argparse
import csv
import html
import json
import math
import statistics
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COUNTS = ('bytes_out', 'dns_queries', 'dns_failures', 'distinct_ports', 'syn_packets', 'synack_packets')
FEATURES = ('log_bytes_out', 'dns_failure_ratio', 'distinct_ports', 'syn_failure_ratio')


def load_rows(path):
    with open(path, encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        required = {'timestamp', 'host', *COUNTS}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('Missing columns: ' + ', '.join(sorted(required - set(reader.fieldnames or []))))
        rows = []
        for line, raw in enumerate(reader, 2):
            row = {k: raw.get(k, '') for k in ('timestamp', 'host', 'label')}
            if not row['timestamp'] or not row['host']:
                raise ValueError(f'Line {line}: timestamp and host are required')
            for k in COUNTS:
                try:
                    value = float(raw[k])
                except (ValueError, TypeError):
                    raise ValueError(f'Line {line}: invalid {k}') from None
                if not math.isfinite(value) or value < 0 or not value.is_integer():
                    raise ValueError(f'Line {line}: {k} must be a finite nonnegative integer')
                row[k] = int(value)
            if row['dns_failures'] > row['dns_queries'] or row['synack_packets'] > row['syn_packets']:
                raise ValueError(f'Line {line}: response/failure counts exceed request counts')
            rows.append(row)
        if not rows:
            raise ValueError('CSV contains no data rows')
        return rows


def features(row):
    return (math.log1p(row['bytes_out']),
            row['dns_failures'] / max(1, row['dns_queries']),
            row['distinct_ports'],
            (row['syn_packets'] - row['synack_packets']) / max(1, row['syn_packets']))


def fit(rows):
    if len(rows) < 10:
        raise ValueError('Provide at least 10 known-normal training windows')
    columns = list(zip(*(features(r) for r in rows)))
    return {'version': 1, 'threshold': 4.0, 'training_windows': len(rows),
            'means': [statistics.mean(c) for c in columns],
            'scales': [max(statistics.stdev(c), floor) for c, floor in zip(columns, (0.2, 0.03, 2.0, 0.04))]}


def analyze(row, model):
    values = features(row)
    zs = [max(0.0, (x - mu) / sd) for x, mu, sd in zip(values, model['means'], model['scales'])]
    score = max(zs)
    evidence, steps = [], []
    if values[1] > .25 and row['dns_queries'] >= 10:
        evidence.append(f"DNS failure ratio {values[1]:.0%} ({row['dns_failures']}/{row['dns_queries']})")
        steps.append('Check the configured resolver and compare one known domain against an approved alternate resolver. A DNS failure does not prove an attack.')
    if row['distinct_ports'] > 30 and values[3] > .5:
        evidence.append(f"{row['distinct_ports']} distinct destination ports; {values[3]:.0%} SYNs without a matching SYN-ACK in this window")
        steps.append('Check whether an authorized inventory or scan is running. Review firewall logs and capture timing before treating this as hostile scanning.')
    if zs[0] >= model['threshold']:
        evidence.append(f"Outbound volume {row['bytes_out'] / 1_000_000:.2f} MB; log-volume deviation {zs[0]:.1f} baseline SD")
        steps.append('Check scheduled backups, cloud sync and software updates; identify the owning process before considering containment.')
    flagged = score >= model['threshold']
    if not evidence:
        evidence.append('No matched diagnostic pattern; inspect the largest feature deviation.' if flagged else 'Within the learned normal baseline for these four features.')
    if not steps:
        steps.append('Review baseline representativeness and inspect source logs.' if flagged else 'Continue monitoring; normal score does not establish that the host is safe.')
    return {**row, 'flagged': flagged, 'score': round(score, 3),
            'top_feature': FEATURES[zs.index(max(zs))], 'evidence': evidence, 'next_steps': steps,
            'explanation_backend': 'deterministic templates; no LLM or accelerator used'}


def evaluate(results):
    labeled = [r for r in results if r.get('label') in ('normal', 'dns', 'scan', 'upload')]
    if not labeled:
        return None
    tp = sum(r['flagged'] and r['label'] != 'normal' for r in labeled)
    fp = sum(r['flagged'] and r['label'] == 'normal' for r in labeled)
    fn = sum(not r['flagged'] and r['label'] != 'normal' for r in labeled)
    tn = len(labeled) - tp - fp - fn
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=tp / max(1, tp + fp), recall=tp / max(1, tp + fn))


def write_report(results, path):
    esc = lambda x: html.escape(str(x))
    cards = []
    for r in sorted(results, key=lambda x: x['score'], reverse=True):
        evidence = ''.join('<li>' + esc(x) + '</li>' for x in r['evidence'])
        steps = ''.join('<li>' + esc(x) + '</li>' for x in r['next_steps'])
        cards.append(f'<article><span class="tag">{"REVIEW" if r["flagged"] else "BASELINE"}</span><h2>{esc(r["host"])}</h2><p>{esc(r["timestamp"])} · Score {r["score"]:.2f} · {esc(r["top_feature"])}</p><ul>{evidence}</ul><h3>Next steps</h3><ul>{steps}</ul></article>')
    count = sum(r['flagged'] for r in results)
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NetGuardian | Local analysis</title>
<style>body{background:#0b1525;color:#e7eef8;font:16px/1.6 system-ui;margin:0}main{max-width:1100px;margin:auto;padding:48px 24px}h1{font-size:48px;margin:8px 0;color:#65e0cb}h2{margin:8px 0}p{color:#afbed1}.stats{font-size:24px;margin:28px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}article{background:#13243b;border:1px solid #294059;padding:24px;border-radius:14px}.tag{font-size:12px;letter-spacing:2px;color:#65e0cb}h3{font-size:14px;text-transform:uppercase;color:#65e0cb}aside{border-left:3px solid #65e0cb;padding:12px 20px;background:#13243b;margin:24px 0}</style><main><span class="tag">LOCAL TELEMETRY / HUMAN REVIEW</span><h1>NetGuardian</h1><p>From network symptoms to evidence and a next step.</p>'''
    page += f'<div class="stats">{len(results)} windows &nbsp; / &nbsp; {count} flagged &nbsp; / &nbsp; no cloud calls</div>'
    page += '<aside>Prototype: learned statistical baseline + template explanations. Bundled data is synthetic. No live capture, LLM inference, automatic blocking, or UGen300 execution is implemented.</aside><div class="grid">' + ''.join(cards) + '</div></main></html>'
    Path(path).write_text(page, encoding='utf-8')


def run(input_path, training_path, output_dir):
    model = fit(load_rows(training_path))
    rows = load_rows(input_path)
    started = time.perf_counter()
    results = [analyze(r, model) for r in rows]
    elapsed = (time.perf_counter() - started) * 1000
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = {'windows': len(results), 'flagged': sum(r['flagged'] for r in results),
               'analysis_ms': round(elapsed, 3), 'metrics': evaluate(results),
               'scope': 'Bundled synthetic data only; not a real-world detection benchmark.'}
    (out / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    (out / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    (out / 'baseline.json').write_text(json.dumps(model, indent=2), encoding='utf-8')
    write_report(results, out / 'report.html')
    return summary


def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox
    import webbrowser
    root = tk.Tk()
    root.title('NetGuardian | Offline network triage')
    root.geometry('800x560')
    root.configure(bg='#0b1525')
    def label(text, size=14, color='#e7eef8'):
        tk.Label(root, text=text, font=('Arial', size), fg=color, bg='#0b1525', wraplength=700, justify='left').pack(anchor='w', padx=40, pady=12)
    label('NETGUARDIAN', 30, '#65e0cb')
    label('From network symptoms to a next step.', 19)
    label('Offline prototype · statistical baseline + evidence templates\nNo cloud API, live capture, LLM, or UGen300 execution.')
    status = tk.StringVar(value='Choose the bundled synthetic demo or import 60-second telemetry windows.')
    def execute(path):
        try:
            summary = run(path, ROOT / 'data/train_normal.csv', ROOT / 'output')
            status.set(f"{summary['windows']} windows analyzed | {summary['flagged']} flagged\nReport saved in output/report.html")
            webbrowser.open((ROOT / 'output/report.html').as_uri())
        except (OSError, ValueError) as e:
            messagebox.showerror('Cannot analyze input', str(e))
    for text, action in [('Run synthetic demo', lambda: execute(ROOT / 'data/demo.csv')),
                         ('Import telemetry CSV', lambda: choose())]:
        tk.Button(root, text=text, command=action, font=('Arial', 14), bg='#65e0cb', fg='#0b1525', relief='flat', padx=20, pady=10).pack(anchor='w', padx=40, pady=8)
    def choose():
        path = filedialog.askopenfilename(filetypes=[('Telemetry CSV', '*.csv')])
        if path:
            execute(path)
    tk.Label(root, textvariable=status, font=('Arial', 12), fg='#afbed1', bg='#0b1525', wraplength=700, justify='left').pack(anchor='w', padx=40, pady=24)
    root.mainloop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gui', action='store_true')
    parser.add_argument('--input', type=Path, default=ROOT / 'data/demo.csv')
    parser.add_argument('--train', type=Path, default=ROOT / 'data/train_normal.csv')
    parser.add_argument('--output', type=Path, default=ROOT / 'output')
    args = parser.parse_args()
    if args.gui:
        gui()
    else:
        try:
            print(json.dumps(run(args.input, args.train, args.output), indent=2))
        except (OSError, ValueError) as error:
            parser.exit(2, f'Input error: {error}\n')
