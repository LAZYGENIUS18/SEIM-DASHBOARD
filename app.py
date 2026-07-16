# CyberShield — SIEM Dashboard

![Python](https://img.shields.io/badge/python-3.13-blue)
![Flask](https://img.shields.io/badge/backend-Flask-black)
![License](https://img.shields.io/badge/license-MIT-green)

A full-stack security operations dashboard. The Flask backend detects which
CLI security tools are actually installed on your machine, executes them via
subprocess when you launch a scan, streams live output to the browser over
WebSocket, normalizes results into a common event schema, stores everything
in SQLite, and visualizes it all in a dark-themed SOC-style frontend.

> ⚠️ **Only run these tools against systems you own or are explicitly
> authorized to test.** Scanning third-party systems without permission is
> illegal in most jurisdictions. This dashboard does not enforce
> authorization — that responsibility is yours.

## Quick start

```bash
cd cybershield-dashboard
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5000**. The Tool Center will show which of the 17
configured tools are available on your `PATH`. Only `httpx` (via the Python
`httpx` library) ships pre-wired and installed — everything else needs the
install step listed on its card.

## Installing additional tools

| Tool | Install |
|---|---|
| Nmap | `winget install nmap` or https://nmap.org |
| Subfinder / Nuclei / Katana / Gau / Naabu | Go binaries from ProjectDiscovery's GitHub releases |
| ffuf | https://github.com/ffuf/ffuf/releases |
| RustScan | https://github.com/RustScan/RustScan/releases |
| Dalfox | https://github.com/hahwul/dalfox/releases |
| LinkFinder | `pip install linkfinder` |
| MobSF | `pip install mobsf` |
| JADX | https://github.com/skylot/jadx/releases (needs Java) |
| Frida | `pip install frida-tools` |
| John the Ripper | https://github.com/openwall/john |
| Wireshark (tshark) | `winget install wireshark` |
| Postman (newman) | `npm install -g newman` |

Once a binary is on `PATH`, refresh the Tool Center — no code changes needed.
Tool definitions (command templates, parameters, parsers) live in
`tools_config.json`, so adding a new tool is a config change, not a code
change.

## Project layout

```
cybershield-dashboard/
├── app.py                # Flask app: REST API, WebSocket, tool executor, correlation engine
├── parsers.py             # Per-tool output → normalized event parsers
├── tools_config.json      # Declarative config for all 17 tools
├── requirements.txt
└── static/
    ├── index.html         # 6-tab dashboard shell
    ├── style.css           # Dark glassmorphism SOC design system
    └── app.js              # WebSocket client, Chart.js visuals, tool launcher, forensic pivot
```

## How a scan flows through the system

1. You pick a tool in **Tool Center**, fill in parameters, click **Launch**.
2. The backend validates params (rejects shell metacharacters), builds an
   argv list (no shell involved), and runs the tool in a background thread.
3. Stdout/stderr streams line-by-line to every connected browser tab over
   `/ws`, rendered live in **Live Terminal**.
4. When the process exits, `parsers.py` normalizes its raw output into
   events: `{timestamp, severity, source_ip, host, finding_type, message}`.
5. Events are written to SQLite (`cybershield.db`) and broadcast to the
   **Live Event Ticker**, **Findings & Events** table, and the Overview
   charts (shield score, trend, risk doughnut, module radar).
6. A lightweight correlation engine flags hosts with 3+ clustered findings
   as a combined-risk alert.
7. **Forensic Investigator** lets you pivot by host/IP, walk the timeline,
   and inspect full event JSON. **Report Generator** (Export buttons) writes
   out CSV or JSON of everything recorded.

## Security notes on this implementation

- Tool arguments are passed as an argv list directly to `subprocess.Popen`
  (never through a shell), and every parameter is checked against an
  allow-list regex before it reaches the command line.
- Tools that aren't detected on `PATH` are hard-blocked from running
  server-side (not just hidden in the UI) — the `/api/tools/<id>/run`
  endpoint returns a 400 if the binary isn't available.
- `cybershield.db` is created fresh in the project directory on first run
  and holds every run and finding locally — nothing is sent off-machine.

## License

MIT — see [LICENSE](LICENSE).
