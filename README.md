# PCC Scout

Pre-deployment network assessment tool for Precision Computers & Consulting.

## Use Cases

- **Pre-Sales**: Run on a prospect's network to generate a branded PDF report
- **Onboarding/Audit**: Run against existing clients to populate baseline documentation

## Requirements

- Node.js 18+
- nmap installed and in PATH
  - macOS: `brew install nmap`
  - Windows: `choco install nmap`
  - Linux: `sudo apt install nmap`

## Quick Start

```bash
npm install
npm start
```

## How It Works

1. Configure branding (company name, logo, accent color) on first launch
2. Enter target subnet and scan label
3. PCC Scout runs nmap discovery + port scanning + security flag analysis
4. Review results in the app
5. Generate a branded PDF report or export raw JSON

## Project Structure

```
src/
  main.js           Electron main process
  preload.js        Context bridge (IPC)
  renderer/         UI (vanilla HTML/CSS/JS)
  scanner/          Network discovery + security analysis
  report/           PDF report generation via Puppeteer
config/             Branding config (gitignored)
output/             Generated PDFs (gitignored)
assets/             Logos and static assets
```

## Phase Roadmap

- **Phase 1** (current): Network discovery, port scanning, OS fingerprint, security flags, PDF report
- **Phase 2**: AD enumeration, SMB/WMI deep inspection, Windows-specific checks
- **Phase 3**: DocHub integration for baseline documentation import
