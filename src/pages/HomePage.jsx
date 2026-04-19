import { Link } from 'react-router-dom';
import { ArrowRight, Shield, Zap, GitBranch, BarChart2 } from 'lucide-react';

const FEATURES = [
  { icon: Zap,       title: 'Static Analysis',     desc: 'Hash verification, entropy scanning, and suspicious API call detection before execution.' },
  { icon: GitBranch, title: 'Threat Intelligence', desc: 'Cross-referenced against global reputation databases and MITRE ATT&CK mappings.' },
  { icon: BarChart2, title: 'Risk Scoring',        desc: 'Weighted composite score: Risk = 0.35×S + 0.40×D + 0.25×T.' },
  { icon: Shield,    title: 'Mitigation Guidance', desc: 'Actionable, prioritised response steps generated alongside every report.' },
  { icon: ArrowRight, title: 'Graph Orchestration', desc: 'Switch between CrewAI and LangGraph while keeping one report schema and LangSmith-ready tracing hooks.' },
];

const ARCH = [
  { label: 'React SPA',     sub: 'Frontend'         },
  { label: 'FastAPI',       sub: 'API Gateway'       },
  { label: 'CrewAI / LangGraph', sub: 'Orchestrators' },
  { label: 'Groq AI Agent', sub: 'LLM Backbone'      },
  { label: 'Threat Intel',  sub: 'External APIs'    },
];

const TERMINAL = [
  '$ aegis --target invoice_Q4.exe',
  '',
  '[1/3] Static analysis ............. done',
  '[2/3] Dynamic analysis ............ done',
  '[3/3] Threat intelligence ......... done',
  '',
  'VERDICT    MALICIOUS',
  'SCORE      87 / 100',
  'ACTION     File quarantined.',
];
export default function HomePage() {
  return (
    <div className="dot-grid flex-1">

      {/* Hero */}
      <section className="py-24 px-6 border-b border-bw-border">
        <div className="max-w-7xl mx-auto grid lg:grid-cols-2 gap-16 items-center">

          {/* Copy */}
          <div className="space-y-7">
            <div className="inline-flex items-center gap-2 border border-bw-border rounded text-[11px] tracking-widest text-bw-sub px-3 py-1.5 uppercase">
              <span className="w-1.5 h-1.5 rounded-full bg-bw-sub" />
              AI-Driven Threat Analysis
            </div>

            <h1 className="text-4xl sm:text-5xl font-bold tracking-tight leading-tight text-bw-white">
              Detect threats<br />before they strike.
            </h1>

            <p className="text-bw-sub leading-relaxed max-w-md text-sm">
              Aegis runs every file and URL through a three-phase AI pipeline —
              static inspection, dynamic analysis, and live threat intelligence —
              with CrewAI and LangGraph orchestration options to deliver a quantified risk verdict in seconds.
            </p>

            <div className="flex flex-wrap items-center gap-4">
              <Link
                to="/scan"
                className="flex items-center gap-2 px-5 py-2.5 bg-bw-white text-bw-bg text-xs font-bold tracking-widest uppercase rounded hover:bg-bw-text transition-colors"
              >
                Start Scanning <ArrowRight size={14} />
              </Link>
              <a href="#architecture" className="text-xs text-bw-sub tracking-widest uppercase hover:text-bw-text transition-colors">
                Architecture →
              </a>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              {[
                { v: '3-Phase', l: 'Pipeline'     },
                { v: '2',       l: 'Engines'       },
                { v: 'Groq',    l: 'AI Engine'     },
                { v: '70+',     l: 'AV Coverage*'  },
              ].map(({ v, l }) => (
                <div key={l} className="border border-bw-border rounded p-3 bg-bw-panel">
                  <p className="text-bw-white font-bold text-base font-mono">{v}</p>
                  <p className="text-bw-muted text-[10px] tracking-wide mt-0.5">{l}</p>
                </div>
              ))}
            </div>
            <p className="text-[9px] text-bw-muted">* Simulated — academic demo</p>
          </div>

          {/* Terminal */}
          <div className="rounded-lg border border-bw-border bg-bw-panel overflow-hidden">
            <div className="flex items-center gap-1.5 px-4 py-2.5 border-b border-bw-border bg-bw-card">
              <span className="w-2.5 h-2.5 rounded-full bg-bw-border2" />
              <span className="w-2.5 h-2.5 rounded-full bg-bw-border2" />
              <span className="w-2.5 h-2.5 rounded-full bg-bw-border2" />
              <span className="ml-2 text-[11px] text-bw-muted">aegis — terminal</span>
            </div>
            <div className="p-5 font-mono text-xs space-y-1.5 min-h-[200px]">
              {TERMINAL.map((line, i) => (
                <p key={i} className={
                  line.startsWith('VERDICT') || line.startsWith('SCORE') || line.startsWith('ACTION')
                    ? 'text-bw-white font-bold'
                    : line.startsWith('$')
                    ? 'text-bw-text'
                    : 'text-bw-sub'
                }>
                  {line || '\u00A0'}
                </p>
              ))}
              <span className="inline-block w-2 h-3.5 bg-bw-sub blink" />
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-20 px-6 border-b border-bw-border">
        <div className="max-w-7xl mx-auto">
          <div className="mb-12">
            <h2 className="text-xl font-bold text-bw-white tracking-tight mb-2">Detection Engine</h2>
            <p className="text-bw-sub text-sm max-w-lg">Three independent analysis phases, orchestrated through CrewAI or LangGraph and powered by the Groq LLM agent.</p>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-px bg-bw-border">
            {FEATURES.map(({ icon: Icon, title, desc }) => (
              <div key={title} className="p-6 bg-bw-bg hover:bg-bw-panel transition-colors">
                <Icon size={16} className="text-bw-sub mb-4" />
                <h3 className="text-bw-text text-sm font-semibold mb-2">{title}</h3>
                <p className="text-bw-muted text-xs leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Architecture */}
      <section id="architecture" className="py-20 px-6 border-b border-bw-border">
        <div className="max-w-5xl mx-auto">
          <div className="mb-12">
            <h2 className="text-xl font-bold text-bw-white tracking-tight mb-2">Architecture</h2>
            <p className="text-bw-sub text-sm">High-level pipeline overview.</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {ARCH.map(({ label, sub }, i) => (
              <div key={label} className="contents">
                <div className="border border-bw-border rounded p-4 bg-bw-panel min-w-[110px] text-center">
                  <p className="text-bw-text text-xs font-bold">{label}</p>
                  <p className="text-bw-muted text-[10px] mt-0.5">{sub}</p>
                </div>
                {i < ARCH.length - 1 && (
                  <ArrowRight size={14} className="text-bw-muted" />
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 px-6">
        <div className="max-w-xl mx-auto text-center space-y-6">
          <h2 className="text-2xl font-bold text-bw-white tracking-tight">Analyse anything, now.</h2>
          <p className="text-bw-sub text-sm">Submit a suspicious file or URL and receive a full AI threat report with mitigation steps in under 15 seconds.</p>
          <Link
            to="/scan"
            className="inline-flex items-center gap-2 px-6 py-3 bg-bw-white text-bw-bg text-xs font-bold tracking-widest uppercase rounded hover:bg-bw-text transition-colors"
          >
            Open Dashboard <ArrowRight size={14} />
          </Link>
        </div>
      </section>

    </div>
  );
}
