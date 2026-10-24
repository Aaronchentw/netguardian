"""Reproducible synthetic fixtures; deliberately separated from real telemetry."""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIELDS = ('timestamp', 'host', 'bytes_out', 'dns_queries', 'dns_failures', 'distinct_ports', 'syn_packets', 'synack_packets', 'label')


def generate(count, seed, anomalies=False):
    rng = random.Random(seed)
    for i in range(count):
        syn = rng.randint(50, 100)
        row = dict(timestamp=(datetime(2026, 10, 24, 9) + timedelta(minutes=i)).isoformat(),
                   host=f'workstation-{i % 5 + 1:02}', bytes_out=rng.randint(100_000, 500_000),
                   dns_queries=rng.randint(30, 60), dns_failures=rng.randint(0, 3),
                   distinct_ports=rng.randint(3, 12), syn_packets=syn, synack_packets=syn-rng.randint(0, 8), label='normal')
        if anomalies and i >= 30:
            kind = ('dns', 'scan', 'upload')[(i - 30) // 10]
            row['label'] = kind
            if kind == 'dns':
                row['dns_failures'] = int(row['dns_queries'] * .8)
            elif kind == 'scan':
                row.update(distinct_ports=rng.randint(80, 140), syn_packets=200, synack_packets=10)
            else:
                row['bytes_out'] = rng.randint(20_000_000, 40_000_000)
        yield row


if __name__ == '__main__':
    (ROOT / 'data').mkdir(exist_ok=True)
    for filename, rows in [('train_normal.csv', generate(120, 11)), ('demo.csv', generate(60, 29, True))]:
        with (ROOT / 'data' / filename).open('w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
