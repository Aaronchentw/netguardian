# NetGuardian

Offline network telemetry triage prototype for ASUS UGen AI League, Workplace AI / Battlefield Lightning.

## Run

Requires Python 3.10+; the analysis pipeline uses only the standard library. The optional desktop launcher also needs Tkinter and a local browser.

```powershell
cd NetGuardian
python make_data.py
python netguardian.py
python netguardian.py --gui
python -m unittest -v
```

Open `output/report.html` for the local report. Results, the learned profile and synthetic evaluation metrics are also saved as JSON in `output/`.

For your own data:

```powershell
python netguardian.py --train your_normal_windows.csv --input your_windows.csv --output your_results
```

Use representative **known-normal** training windows; the bundled baseline describes generated fixtures, not your network. Do not train on an unknown mix of attacks and normal traffic. The prototype has no per-host baselines or automatic threshold calibration.

## Input contract

One row represents one host over one **60-second** window. Required CSV fields:

| Field | Meaning |
|---|---|
| timestamp | Nonempty window timestamp, conventionally ISO 8601 |
| host | Nonempty operator-chosen host identifier |
| bytes_out | Outbound bytes in the window |
| dns_queries | DNS query count |
| dns_failures | Failed queries, at most dns_queries |
| distinct_ports | Number of distinct destination ports |
| syn_packets | Initial TCP SYNs observed in the window |
| synack_packets | Matching SYN-ACKs for those SYNs, at most syn_packets |
| label | Optional evaluation-only label: normal, dns, scan, upload |

All numeric fields must be finite nonnegative integers. An upstream collector must match responses to requests and choose consistent window boundaries. This prototype does not collect, parse or validate packets, or verify the 60-second duration. Delayed DNS/TCP responses may cross windows and distort ratios. Labels never enter feature extraction, training or scoring; `evaluate` uses recognized labels only.

## Model and limits

The model learns mean and sample standard deviation for log(1 + outbound bytes), DNS failure ratio, destination-port count and unmatched-SYN ratio. Floors on standard deviations are 0.2, 0.03, 2.0 and 0.04. The score is the largest positive standardized deviation; the fixed review threshold is 4. Negative deviations and correlations are not modeled. This is a simple one-class statistical baseline, not a trained neural network or comprehensive intrusion detector.

Diagnostic templates inspect DNS failure, scan-like and volume patterns. An explanation suggests checks and benign alternatives; it does not establish malicious intent. No commands are executed, no hosts are blocked, and no network calls occur in analysis. The optional GUI opens a static report with the user's configured browser.

The bundled data has 120 synthetic training windows and 60 separately seeded test windows. Its three anomaly groups are deliberately separable. TP=30, FP=0, FN=0, TN=30 on these fixtures establishes expected pipeline behavior only. It does not establish real-world precision, recall or security effectiveness. Five automated tests cover expected scenarios, label independence, zero counts/unmatched anomalies, invalid counts and HTML escaping.

## UGen300 integration status

**Not implemented or tested on hardware.** Planned Stage II work: a Linux host validates an official supported UGen300 language model, passes minimized structured findings with curated playbook excerpts to local inference, and checks answer structure/evidence references before display. Runtime API availability, model selection, throughput, latency, power and explanation quality remain unverified. If that interface is unavailable, the current template backend remains functional.

Primary references:

- [ASUS UGen300 announcement](https://press.asus.com/news/press-releases/asus-ugen300-usb-ai-accelerator-generative-ai-edge/)
- [Official UGen Utility guide, currently Linux only](https://github.com/Asus-UGen-Series/Ugen-Utility)

## Submission material

- `NetGuardian_Proposal.pptx`: editable 16-slide English proposal.
- `NetGuardian_Proposal_DRAFT.pdf`: PDF draft; participant identity and real links still need completion.
- `slides.json`: editable slide content; `build_slides.ps1` exports it through installed PowerPoint.
- `demo_script.md`: under-three-minute narration and scene plan.
- `NetGuardian_Demo.mp4`: two-minute silent walkthrough using actual generated report screenshots and captions; no hardware execution is shown.
- `NetGuardian_Demo.pptx` + `build_demo.ps1`: editable walkthrough and video export script.
- `submission_checklist.md`: remaining steps before actual submission.

No GitHub repository was published, no YouTube video uploaded, and no competition or course submission performed. Do not submit the draft with placeholder identity or URLs.

After real links and participant details are available, run the following with actual values (installed Microsoft PowerPoint is required for export):

```powershell
python finalize_proposal.py --name "Your Name" --student-id YOUR_ID --github https://github.com/YOUR_ACCOUNT/YOUR_REPO --youtube https://youtu.be/YOUR_VIDEO_ID
```

This rebuilds the deck and creates `{student-id}_CN_league.pdf`. The tool validates URL shape only; open the real links yourself to confirm reviewer access. The demo video is not automatically rebuilt after participant details change.
