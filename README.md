# netScanTool

A local web-based network port scanner built with Python and Flask. 
> **Disclaimer:** This tool is intended and designed for **educational purposes** and for scanning networks you **own or have explicit permission** to scan. Unauthorized port scanning could violate laws and terms of service. Please, use this tool responsibly.

## Features

- **TCP Port Scanning** — Concurrent multi-threaded scanning with adjustable speed
- **Banner Grabbing** — Captures service banners from open ports (SSH, FTP, HTTP, etc.)
- **Preset Port Groups** — Quick-select common ports: Web, Email, Database, Remote Access
- **Custom Port Input** — Enter a comma-separated list or specify a range
- **Throttle Control** — Sneaky, Normal, or Aggressive scan speeds
- **Scan History** — Past scans saved to a local SQLite database
- **Export Results** — Download scan results as CSV or JSON
- **Dark Mode** — Toggleable with smooth transitions, persisted across sessions



## Getting Started

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# Clone the repo
git clone https://github.com/ayatk9n/netScanTool.git
cd netScanTool

# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
python app.py
```

Then, open the localhost in your browser.

## Project Structure

```
netScanTool/
├── app.py              # Flask backend — scanning, history, export
├── requirements.txt    # Python dependencies (flask)
├── templates/
│   └── index.html      # Frontend UI + JavaScript
├── static/
│   └── style.css       #  monospace styling
├── .gitignore
├── LICENSE
└── README.md
```

## How It Works

1. Enter a target IP address or hostname
2. Choose a preset, type a custom port list, or set a range
3. Select scan speed (Sneaky / Normal / Aggressive)
4. Click **► SCAN** — open ports are displayed with service names and banners
5. Export results as CSV/JSON, or review past scans from the history panel

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
