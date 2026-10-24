# NetGuardian

An offline network telemetry triage prototype for ASUS UGen AI League, **Workplace AI / Battlefield Lightning**, with proposed ASUS UGen300 USB integration.

- Participant: 陳睿綸 / b13902029
- [Demonstration video (2 min 44 sec)](https://youtu.be/aZerxq6j_RI)

## Requirements

- Python 3.10 or newer. Analysis and tests use only the Python standard library; no `pip install` step is needed.
- The optional desktop GUI requires Tkinter and a browser. Check Tkinter with `python -m tkinter`. If it is missing, install the Tkinter component for your Python distribution; the command-line analyzer still works without it.
- `Start_NetGuardian.cmd` is a Windows convenience launcher and requires `python` on PATH. Other operating systems can use the Python commands directly.

## Run from a fresh download

Download the repository ZIP and extract it. Open a terminal **inside the extracted folder containing `netguardian.py`**. Its name may be `netguardian-main`.

```powershell
python netguardian.py
```

The included data is ready to use. Expected result: **60 windows analyzed, 30 flagged**. Open `output/report.html` to read the findings; the program also saves `results.json`, `summary.json` and `baseline.json` in `output/`.

To open the desktop interface:

```powershell
python netguardian.py --gui
```

Click **Run synthetic demo**, or click **Import telemetry CSV** and select `data/demo.csv`. The GUI requests that the generated report be opened in your configured browser. If it does not open automatically, open `output/report.html` manually. Each run replaces the files in the selected output folder.

## Reproduce data and tests

```powershell
python make_data.py
python -m unittest -v
```

`make_data.py` deterministically regenerates and overwrites the two bundled synthetic CSVs. Five tests cover held-out scenarios, independence from evaluation labels, zero counts and unmatched anomalies, malformed counts, and HTML escaping.

## Analyze your own telemetry

```powershell
python netguardian.py --train your_normal_windows.csv --input your_windows.csv --output your_results
```

Select representative **known-normal** training windows. The bundled training profile describes generated fixtures, not your network. The GUI uses the bundled training file; use the CLI `--train` option to select a different baseline. This version has no per-host baselines or automatic threshold calibration.

## CSV contract

One row represents one host over a **60-second** window.

| Field | Meaning |
|---|---|
| `timestamp` | Nonempty window timestamp, conventionally ISO 8601 |
| `host` | Nonempty host identifier |
| `bytes_out` | Outbound bytes |
| `dns_queries` | DNS query count |
| `dns_failures` | Failed queries, at most `dns_queries` |
| `distinct_ports` | Number of distinct destination ports |
| `syn_packets` | Initial TCP SYNs |
| `synack_packets` | Matching SYN-ACKs for those SYNs, at most `syn_packets` |
| `label` | Optional evaluation-only label: `normal`, `dns`, `scan`, `upload` |

All numeric fields must be finite nonnegative integers. An upstream collector must match responses to requests and establish consistent windows. This prototype does not capture packets, aggregate flows, verify timestamp format or verify window duration. Responses across window boundaries may distort ratios. Labels are used only for evaluation, never for scoring.

## Model and limitations

The statistical baseline learns means and sample standard deviations for log(1 + outbound bytes), DNS failure ratio, destination-port count, and unmatched-SYN ratio. Standard deviation floors are 0.2, 0.03, 2.0 and 0.04. The score is the largest positive standardized deviation; a score of at least 4 is flagged for review. It is not an attack probability. Negative deviations and feature correlations are not modeled.

Diagnostic templates suggest checks and benign alternatives for DNS failure, scan-like behavior and unusual uploads. No commands are executed and no hosts are blocked. Analysis makes no cloud API calls. Reports and JSON findings remain on the local filesystem.

The 120 training windows and 60 separately seeded test windows are synthetic. The deliberately separated test set yields TP=30, FP=0, FN=0 and TN=30. These results demonstrate pipeline behavior and **do not establish real-world accuracy or security effectiveness**.

## UGen300 status

**Hardware integration and language-model inference are not implemented or tested.** Planned work uses a Linux host, a vendor-supported UGen300 model, structured findings and bounded playbook context, with checked answers and a template fallback. Runtime interface availability, model compatibility, latency, power and explanation quality remain unverified.

- [ASUS UGen300 announcement](https://press.asus.com/news/press-releases/asus-ugen300-usb-ai-accelerator-generative-ai-edge/)
- [Official UGen Utility guide](https://github.com/Asus-UGen-Series/Ugen-Utility)

The demonstration video contains automatically operated real GUI interactions, actual generated reports, synthetic narration and edited explanatory cards. It uses synthetic data and does not show hardware execution.

## Repository files

```text
netguardian.py            Analysis, reporting and optional GUI
make_data.py              Reproducible synthetic fixture generator
test_netguardian.py       Five automated tests
Start_NetGuardian.cmd     Windows GUI launcher
data/train_normal.csv     Synthetic training windows
data/demo.csv             Synthetic demonstration windows
```

The competition proposal PDF, PowerPoint export utilities and video-editing tools are separate submission artifacts and are not included in this repository.
