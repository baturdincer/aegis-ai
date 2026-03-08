import { useState, useRef, useCallback } from 'react';
import { Upload, Link as LinkIcon, Shield, X, AlertTriangle, FileText, Loader2, ChevronRight } from 'lucide-react';
import { analyseFile, analyseUrl } from '../utils/mockAnalysis';
import { saveReport } from '../utils/storage';
import ThreatReport from '../components/ThreatReport';

const ALLOWED_EXT = ['exe','bat','ps1','vbs','js','jar','py','pdf','docx','zip','iso','msi','dmg','sh','php','dll','bin','so'];
const MAX_MB = 50;

function DropZone({ onFile }) {
  const [drag, setDrag] = useState(false);
  const ref = useRef();

  const onDrop = useCallback((e) => {
    e.preventDefault(); setDrag(false);
    const f = e.dataTransfer.files?.[0]; if (f) onFile(f);
  }, [onFile]);

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
      onDragLeave={() => setDrag(false)}
      onDrop={onDrop}
      onClick={() => ref.current?.click()}
      className={`cursor-pointer rounded border-2 border-dashed p-12 flex flex-col items-center gap-4 transition-colors
        ${drag ? 'border-bw-sub bg-bw-panel' : 'border-bw-border hover:border-bw-border2'}`}
    >
      <Upload size={24} className={drag ? 'text-bw-white' : 'text-bw-muted'} />
      <div className="text-center">
        <p className="text-bw-text text-sm">{drag ? 'Release to analyse' : 'Drop a file here'}</p>
        <p className="text-bw-muted text-xs mt-1">or click to browse · max {MAX_MB} MB</p>
        <p className="text-bw-muted text-[10px] mt-2 tracking-wide">
          {ALLOWED_EXT.map(e => e.toUpperCase()).join(' · ')}
        </p>
      </div>
      <input ref={ref} type="file" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value=''; }}
        accept={ALLOWED_EXT.map(e => `.${e}`).join(',')}
      />
    </div>
  );
}

function AnalysisProgress({ stage }) {
  const stages = [
    { key: 'static',  label: 'Static Analysis',    sub: 'Hash · entropy · patterns' },
    { key: 'dynamic', label: 'Dynamic Analysis',   sub: 'AI runtime prediction'          },
    { key: 'intel',   label: 'Threat Intelligence',sub: 'Reputation DB lookup'        },
    { key: 'report',  label: 'Generating Report',  sub: 'Risk scoring · mitigation'  },
  ];
  const cur = stages.findIndex(s => s.key === stage);
  return (
    <div className="border border-bw-border rounded-lg bg-bw-panel p-5 space-y-4">
      <div className="flex items-center gap-2 text-bw-sub text-xs tracking-widest uppercase">
        <Loader2 size={14} className="animate-spin" />
        Analysis in progress
      </div>
      <div className="space-y-3">
        {stages.map((s, i) => {
          const done   = i < cur;
          const active = i === cur;
          return (
            <div key={s.key} className="flex items-center gap-3">
              <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0 transition-colors
                ${done ? 'bg-bw-sub text-bw-bg' : active ? 'bg-bw-white text-bw-bg' : 'bg-bw-card text-bw-muted border border-bw-border'}`}>
                {done ? '✓' : i + 1}
              </div>
              <div className="flex-1">
                <p className={`text-xs font-medium ${active ? 'text-bw-white' : done ? 'text-bw-sub' : 'text-bw-muted'}`}>{s.label}</p>
                <p className={`text-[10px] ${active ? 'text-bw-sub' : 'text-bw-muted'}`}>{s.sub}</p>
              </div>
              {active && (
                <div className="w-16 h-px bg-bw-border overflow-hidden">
                  <div className="h-full bg-bw-white fill-bar" style={{ width: '60%' }} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const [mode, setMode]     = useState('file');
  const [url, setUrl]       = useState('');
  const [file, setFile]     = useState(null);
  const [error, setError]   = useState('');
  const [stage, setStage]   = useState(null);
  const [report, setReport] = useState(null);

  const validateFile = (f) => {
    setError('');
    const ext = f.name.split('.').pop().toLowerCase();
    if (!ALLOWED_EXT.includes(ext)) { setError(`".${ext}" is not supported.`); return false; }
    if (f.size > MAX_MB * 1024 * 1024) { setError(`File exceeds ${MAX_MB} MB.`); return false; }
    return true;
  };

  const handleFileDrop = (f) => { if (validateFile(f)) setFile(f); };
  const removeFile = () => { setFile(null); setError(''); };

  const handleScan = async () => {
    setError('');
    if (mode === 'file' && !file) { setError('Please select a file first.'); return; }
    if (mode === 'url') {
      const t = url.trim();
      if (!t) { setError('Please enter a URL.'); return; }
      if (!t.startsWith('http')) { setError('URL must start with http:// or https://'); return; }
    }

    const order = ['static', 'dynamic', 'intel', 'report'];
    let idx = 0; setStage(order[0]);
    const iv = setInterval(() => { idx = Math.min(idx + 1, order.length - 1); setStage(order[idx]); }, 4000);

    try {
      const result = mode === 'file' ? await analyseFile(file) : await analyseUrl(url.trim());
      saveReport(result);
      setReport(result);
    } catch (e) {
      setError(e.message || 'Analysis failed. Is the backend running?');
    } finally {
      clearInterval(iv); setStage(null);
    }
  };

  const scanning = stage !== null;

  return (
    <div className="flex-1 dot-grid py-12 px-6">
      <div className="max-w-3xl mx-auto space-y-6">

        {/* Header */}
        <div className="border-b border-bw-border pb-5">
          <h1 className="text-xl font-bold text-bw-white tracking-tight">Analysis Dashboard</h1>
          <p className="text-bw-sub text-sm mt-1">Submit a file or URL for AI-driven threat analysis.</p>
        </div>

        {/* Mode toggle */}
        <div className="flex border border-bw-border rounded overflow-hidden w-fit">
          {[{ key: 'file', label: 'File Upload' }, { key: 'url', label: 'URL Scanner' }].map(({ key, label }) => (
            <button key={key}
              onClick={() => { setMode(key); setError(''); setFile(null); setUrl(''); }}
              disabled={scanning}
              className={`px-5 py-2 text-xs tracking-widest uppercase transition-colors
                ${mode === key ? 'bg-bw-white text-bw-bg font-bold' : 'text-bw-sub hover:text-bw-text'}`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Input */}
        <div className="border border-bw-border rounded-lg bg-bw-panel p-5 space-y-4">
          {mode === 'file' ? (
            !file ? <DropZone onFile={handleFileDrop} /> : (
              <div className="flex items-center gap-3 p-4 rounded border border-bw-border2 bg-bw-card">
                <FileText size={16} className="text-bw-sub flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-bw-white text-sm truncate">{file.name}</p>
                  <p className="text-bw-muted text-[11px]">{fmtBytes(file.size)}</p>
                </div>
                {!scanning && (
                  <button onClick={removeFile} className="text-bw-muted hover:text-bw-white transition-colors"><X size={16} /></button>
                )}
              </div>
            )
          ) : (
            <div className="space-y-2">
              <label className="text-[10px] text-bw-muted tracking-widest uppercase">Target URL</label>
              <div className="flex items-center gap-2 border border-bw-border rounded bg-bw-bg px-3 py-2.5 focus-within:border-bw-border2 transition-colors">
                <LinkIcon size={14} className="text-bw-muted flex-shrink-0" />
                <input type="text" value={url} onChange={e => { setUrl(e.target.value); setError(''); }}
                  placeholder="https://suspicious-domain.xyz/payload" disabled={scanning}
                  className="flex-1 bg-transparent text-bw-text placeholder-bw-muted text-sm outline-none"
                  onKeyDown={e => e.key === 'Enter' && !scanning && handleScan()}
                />
                {url && !scanning && <button onClick={() => setUrl('')} className="text-bw-muted hover:text-bw-white transition-colors"><X size={13} /></button>}
              </div>
            </div>
          )}

          {error && (
            <div className="flex items-center gap-2 p-3 rounded border border-bw-border2 text-bw-sub text-xs">
              <AlertTriangle size={13} className="flex-shrink-0" />{error}
            </div>
          )}

          <button onClick={handleScan} disabled={scanning}
            className={`w-full flex items-center justify-center gap-2 py-2.5 rounded text-xs font-bold tracking-widest uppercase transition-colors
              ${scanning ? 'bg-bw-card text-bw-muted cursor-not-allowed' : 'bg-bw-white text-bw-bg hover:bg-bw-text'}`}
          >
            {scanning ? <><Loader2 size={14} className="animate-spin" /> Analysing…</> : <><ChevronRight size={14} /> Run Analysis</>}
          </button>
        </div>

        {scanning && <AnalysisProgress stage={stage} />}

        <div className="grid sm:grid-cols-3 gap-3 text-xs">
          {[
            { title: 'Stateless',    desc: 'Each analysis request is fully independent' },
            { title: 'Confidential', desc: 'Submitted samples are not retained'    },
            { title: 'Detailed',     desc: 'Phase-by-phase findings + mitigation'  },
          ].map(({ title, desc }) => (
            <div key={title} className="border border-bw-border rounded p-4 bg-bw-panel">
              <p className="font-bold text-bw-sub mb-1 uppercase tracking-widest text-[10px]">{title}</p>
              <p className="text-bw-muted leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      {report && <ThreatReport report={report} onClose={() => { setReport(null); setFile(null); setUrl(''); }} />}
    </div>
  );
}

function fmtBytes(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B','KB','MB','GB'], i = Math.floor(Math.log(b)/Math.log(k));
  return `${(b/Math.pow(k,i)).toFixed(1)} ${s[i]}`;
}
