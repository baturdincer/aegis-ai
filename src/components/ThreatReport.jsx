import { X, ChevronDown, ChevronUp, FileText, Link } from 'lucide-react';
import { useState } from 'react';
import { RiskGaugeContainer } from './RiskGauge';

const VERDICT = {
  MALICIOUS:  { text: 'text-bw-white',  border: 'border-bw-border2', bg: 'bg-bw-card'  },
  SUSPICIOUS: { text: 'text-bw-sub',    border: 'border-bw-border',  bg: 'bg-bw-panel' },
  CLEAN:      { text: 'text-bw-muted',  border: 'border-bw-border',  bg: 'bg-bw-panel' },
};

const STATUS = {
  alert: { dot: 'bg-bw-white',   label: 'THREAT', text: 'text-bw-white'  },
  warn:  { dot: 'bg-bw-sub',     label: 'WARN',   text: 'text-bw-sub'   },
  ok:    { dot: 'bg-bw-muted',   label: 'OK',     text: 'text-bw-muted' },
};

function Finding({ item }) {
  const s = STATUS[item.status] || STATUS.ok;
  return (
    <div className="flex items-start gap-3 py-2 border-t border-bw-border">
      <span className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${s.dot}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-bw-text text-xs font-medium">{item.label}</span>
          <span className={`text-[9px] tracking-widest ${s.text}`}>{s.label}</span>
        </div>
        <p className="text-bw-sub text-[11px] leading-relaxed">{item.detail}</p>
      </div>
    </div>
  );
}

function PhasePanel({ phase }) {
  const [open, setOpen] = useState(true);
  const alerts = phase.findings.filter(f => f.status === 'alert').length;
  const warns  = phase.findings.filter(f => f.status === 'warn').length;
  return (
    <div className="border border-bw-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 bg-bw-panel hover:bg-bw-card transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="text-xs font-bold tracking-widest text-bw-text uppercase">{phase.name}</span>
          {alerts > 0 && <span className="text-[10px] text-bw-white border border-bw-border2 px-1.5 py-0.5 rounded">{alerts} threat{alerts > 1 ? 's' : ''}</span>}
          {warns  > 0 && <span className="text-[10px] text-bw-sub  border border-bw-border  px-1.5 py-0.5 rounded">{warns} warn{warns > 1 ? 's' : ''}</span>}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-bw-sub">{phase.score}/100</span>
          {open ? <ChevronUp size={14} className="text-bw-muted" /> : <ChevronDown size={14} className="text-bw-muted" />}
        </div>
      </button>
      {open && (
        <div className="px-4 pb-3 bg-bw-bg">
          {phase.findings.map((f, i) => <Finding key={i} item={f} />)}
        </div>
      )}
    </div>
  );
}

function ScoreBar({ label, score }) {
  const w = `${score}%`;
  const color = score >= 70 ? '#fff' : score >= 40 ? '#888' : '#444';
  return (
    <div>
      <div className="flex justify-between mb-1">
        <span className="text-[10px] text-bw-muted tracking-widest uppercase">{label}</span>
        <span className="text-[11px] font-mono text-bw-sub">{score}</span>
      </div>
      <div className="h-px bg-bw-border overflow-hidden">
        <div className="h-full fill-bar" style={{ width: w, backgroundColor: color }} />
      </div>
    </div>
  );
}

export default function ThreatReport({ report, onClose }) {
  if (!report) return null;
  const vc = VERDICT[report.verdict] || VERDICT.CLEAN;
  const short = report.target.length > 55 ? report.target.slice(0, 52) + '…' : report.target;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className={`relative w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-lg border ${vc.border} bg-bw-bg`}>

        {/* Header */}
        <div className="sticky top-0 z-10 flex items-center justify-between px-5 py-4 border-b border-bw-border bg-bw-bg">
          <div>
            <div className="flex items-center gap-3">
              <span className={`text-sm font-bold tracking-widest uppercase ${vc.text}`}>
                {report.verdict}
              </span>
              <span className="text-bw-muted text-xs">·</span>
              <span className="text-bw-sub text-xs">Risk Score: {report.riskScore}/100</span>
            </div>
            <p className="text-bw-muted text-[11px] mt-0.5">
              {new Date(report.timestamp).toLocaleString()} · {report.targetType === 'file' ? 'File' : 'URL'}
            </p>
          </div>
          <button onClick={onClose} className="text-bw-muted hover:text-bw-white transition-colors p-1">
            <X size={18} />
          </button>
        </div>

        <div className="p-5 space-y-5">

          {/* Summary row */}
          <div className="grid grid-cols-3 gap-4 p-4 border border-bw-border rounded-lg bg-bw-panel">
            <div className="col-span-1 flex flex-col items-center justify-center border-r border-bw-border">
              <RiskGaugeContainer score={report.riskScore} size={110} />
            </div>
            <div className="col-span-2 space-y-3 pl-2">
              <div>
                <p className="text-[10px] text-bw-muted tracking-widest uppercase mb-1">
                  {report.targetType === 'file' ? 'File' : 'URL'}
                </p>
                <p className="text-bw-text text-xs font-mono break-all">{short}</p>
              </div>
              <div className="space-y-2 pt-2 border-t border-bw-border">
                <ScoreBar label="Static"  score={report.scores.static}  />
                <ScoreBar label="Dynamic" score={report.scores.dynamic} />
                <ScoreBar label="Intel"   score={report.scores.intel}   />
              </div>
            </div>
          </div>

          {/* Phases */}
          <div className="space-y-2">
            <p className="text-[10px] text-bw-muted tracking-widest uppercase">Findings</p>
            <PhasePanel phase={report.phases.static}  />
            <PhasePanel phase={report.phases.dynamic} />
            <PhasePanel phase={report.phases.intel}   />
          </div>

          {/* Mitigation */}
          <div className="border border-bw-border rounded-lg bg-bw-panel p-4">
            <p className="text-[10px] text-bw-muted tracking-widest uppercase mb-3">Recommended Actions</p>
            <ol className="space-y-2">
              {(report.mitigation || []).map((action, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-bw-text">
                  <span className="text-bw-muted font-mono flex-shrink-0">{String(i+1).padStart(2,'0')}.</span>
                  {action}
                </li>
              ))}
            </ol>
          </div>

        </div>
      </div>
    </div>
  );
}
