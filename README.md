# Aegis — AI-Driven Phishing & Threat Analysis Center

> Advanced Web Development — Homework 2
> Multi-phase file and URL threat analysis platform with a dark-mode SOC interface.

---

## Project Description

Aegis is a React-based web application that simulates a professional Security Operations Center (SOC) tool. Users can submit suspicious files or URLs and receive a comprehensive, AI-generated threat report — including static analysis, sandbox behavioural simulation, and threat intelligence cross-referencing — in seconds.

The current version uses a **client-side mock analysis engine** that deterministically simulates the full agent pipeline. Real API integrations (VirusTotal, AbuseIPDB, Docker sandbox) are planned for future assignments.

---

## Features

| Feature | Description |
|---|---|
| File Drag-and-Drop | Analyse EXE, PDF, PS1, ZIP, and 15+ other formats |
| URL Scanner | Phishing pattern detection, redirect chain analysis |
| 3-Phase Pipeline | Static → Dynamic (Sandbox) → Threat Intelligence |
| Risk Score (0–100) | Weighted composite score with CLEAN / SUSPICIOUS / MALICIOUS verdict |
| Detailed Report Modal | Phase-by-phase findings with SVG risk gauge |
| Mitigation Steps | Prioritised, actionable response recommendations |
| Scan History | LocalStorage-persisted history with search, filter, and drill-down |
| Dark Mode UI | Professional cyber / SOC aesthetic using Tailwind CSS |

---

## Tech Stack

- **Frontend:** React 18 + Vite 7
- **Styling:** Tailwind CSS v3 (dark theme)
- **Routing:** React Router v6
- **Icons:** Lucide React
- **Analysis Engine:** Custom deterministic mock (`src/utils/mockAnalysis.js`)
- **Persistence:** Browser LocalStorage

---

## Getting Started

### Prerequisites

- Node.js 18+ and npm 9+

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/aegis-ai.git
cd aegis-ai

# Install dependencies
npm install
```

### Running Locally

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Production Build

```bash
npm run build
npm run preview   # preview the built output locally
```

---

## Deployment

### Vercel (Recommended)

```bash
npm install -g vercel
vercel
```

### GitHub Pages

1. Add `"homepage": "https://<user>.github.io/<repo>"` to `package.json`.
2. Install `gh-pages`:
   ```bash
   npm install -D gh-pages
   ```
3. Add to `package.json` scripts:
   ```json
   "predeploy": "npm run build",
   "deploy": "gh-pages -d dist"
   ```
4. Run:
   ```bash
   npm run deploy
   ```

> **Note:** Because Aegis uses client-side routing (React Router), configure a `404.html` redirect or use `HashRouter` for GitHub Pages compatibility.

---

## Project Structure

```
aegis-ai/
├── public/
├── src/
│   ├── components/
│   │   ├── Navbar.jsx          # Sticky navigation with active links
│   │   ├── Footer.jsx          # Footer with system status indicator
│   │   ├── RiskGauge.jsx       # SVG circular risk score visualisation
│   │   └── ThreatReport.jsx    # Full-detail report modal
│   ├── pages/
│   │   ├── HomePage.jsx        # Hero, features, architecture overview
│   │   ├── DashboardPage.jsx   # File upload + URL scanner + progress
│   │   └── HistoryPage.jsx     # Filterable scan history table
│   ├── utils/
│   │   ├── mockAnalysis.js     # Deterministic mock analysis engine
│   │   └── storage.js          # LocalStorage helpers
│   ├── App.jsx                 # Router + layout wrapper
│   ├── main.jsx                # React entry point
│   └── index.css               # Tailwind directives + custom utilities
├── docs/
│   └── AI_Agent_Planning.md    # AI Agent planning document (Part 2)
├── index.html
├── tailwind.config.js
├── vite.config.js
└── package.json
```

---

## 📄 Documentation

### Homework Assignment Documentation

The comprehensive homework documentation is available in LaTeX format:

**File:** `HOMEWORK2_DOCUMENTATION.tex`

**Contents:**
- Project overview and objectives
- Target users and core features
- Technical implementation details (UI only)
- AI agent planning and concept
- System architecture (current and planned)
- Future integration roadmap

**To compile the LaTeX document:**
```bash
pdflatex HOMEWORK2_DOCUMENTATION.tex
```

Or use [Overleaf](https://www.overleaf.com) to compile online (upload the .tex file).

### AI Agent Planning Document

The original AI agent planning document is available at:

**[`docs/AI_Agent_Planning.md`](./docs/AI_Agent_Planning.md)** (if included)

It covers:
- Project overview and target users
- Security Analyst Agent concept and workflow
- 3-phase analysis pipeline (Static → Dynamic → Threat Intel)
- Risk score formula with weighted coefficients
- High-level system architecture diagram
- Future roadmap for real API integrations

---

## How the Mock Engine Works

`src/utils/mockAnalysis.js` simulates the full pipeline deterministically:

1. A **seeded pseudo-random number generator** derived from the file name/URL string ensures consistent results for the same input.
2. **Static score** is computed from file extension risk tables and URL pattern matching.
3. **Dynamic score** simulates sandbox findings (C2 contact, registry writes, privilege escalation) based on the static risk level.
4. **Threat intelligence score** simulates AV engine hits and reputation data.
5. The **weighted formula** `Risk = 0.35S + 0.40D + 0.25T` produces the final verdict.

---

## License

MIT

---

## Author

Developed for the Advanced Web Development course.
AI agent architecture based on Ed Donner's *AI Agents* curriculum.
