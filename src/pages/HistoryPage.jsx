import { useState, useEffect } from 'react';
import { Clock, Trash2, Eye, Search, X } from 'lucide-react';
import { getHistory, clearHistory, deleteReport } from '../utils/storage';
import ThreatReport from '../components/ThreatReport';

const VERDICT_STYLE = {
  MALICIOUS:  'text-bw-white',
  SUSPICIOUS: 'text-bw-sub',
  CLEAN:      'text-bw-muted',
};

function Row({ r, onView, onDelete }) {
  const vc = VERDICT_STYLE[r.verdict] || 'text-bw-muted';
  const engine = r.engine === 'langgraph' ? 'LangGraph' : r.engine === 'crew' ? 'CrewAI' : r.engine || 'Heuristic';
  return (
    <tr className="border-t border-bw-border hover:bg-bw-panel transition-colors group">
      <td className="px-4 py-3 max-w-[220px]">
        <p className="text-bw-text text-xs font-mono truncate" title={r.target}>{r.target}</p>
      </td>
      <td className="px-4 py-3">
        <div className="space-y-1">
          <span className="text-bw-muted text-[10px] uppercase tracking-wide block">{r.targetType}</span>
          <span className="text-bw-muted text-[9px] uppercase tracking-widest block">{engine}</span>
        </div>
      </td>
      <td className="px-4 py-3">
        <span className={`text-xs font-bold tracking-widest uppercase ${vc}`}>{r.verdict}</span>
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <div className="w-14 h-px bg-bw-border overflow-hidden">
            <div className="h-full fill-bar"
              style={{ width: `${r.riskScore}%`, backgroundColor: r.riskScore >= 70 ? '#fff' : r.riskScore >= 40 ? '#888' : '#444' }}
            />
          </div>
          <span className="text-xs font-mono text-bw-sub">{r.riskScore}</span>
        </div>
      </td>
      <td className="px-4 py-3 text-bw-muted text-[11px]">{new Date(r.timestamp).toLocaleString()}</td>
      <td className="px-4 py-3">
        <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <button onClick={() => onView(r)} className="p-1.5 text-bw-muted hover:text-bw-white transition-colors" title="View"><Eye size={13} /></button>
          <button onClick={() => onDelete(r.id)} className="p-1.5 text-bw-muted hover:text-bw-white transition-colors" title="Delete"><Trash2 size={13} /></button>
        </div>
      </td>
    </tr>
  );
}

export default function HistoryPage() {
  const [history, setHistory]     = useState([]);
  const [search, setSearch]       = useState('');
  const [filter, setFilter]       = useState('ALL');
  const [viewReport, setView]     = useState(null);
  const [confirmClear, setConfirm]= useState(false);

  useEffect(() => { setHistory(getHistory()); }, []);

  const handleDelete = (id) => setHistory(deleteReport(id));
  const handleClear  = () => { clearHistory(); setHistory([]); setConfirm(false); };

  const counts = {
    ALL:        history.length,
    MALICIOUS:  history.filter(r => r.verdict === 'MALICIOUS').length,
    SUSPICIOUS: history.filter(r => r.verdict === 'SUSPICIOUS').length,
    CLEAN:      history.filter(r => r.verdict === 'CLEAN').length,
  };

  const filtered = history.filter(r =>
    r.target.toLowerCase().includes(search.toLowerCase()) &&
    (filter === 'ALL' || r.verdict === filter)
  );

  return (
    <div className="flex-1 dot-grid py-12 px-6">
      <div className="max-w-6xl mx-auto space-y-6">

        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-bw-border pb-5">
          <div>
            <h1 className="text-xl font-bold text-bw-white tracking-tight">Scan History</h1>
            <p className="text-bw-sub text-sm mt-1">{history.length} scan{history.length !== 1 ? 's' : ''} stored locally</p>
          </div>
          {history.length > 0 && (
            confirmClear ? (
              <div className="flex items-center gap-2 text-xs">
                <span className="text-bw-sub">Clear all?</span>
                <button onClick={handleClear} className="px-3 py-1.5 border border-bw-border2 text-bw-white rounded text-xs hover:bg-bw-card transition-colors">Confirm</button>
                <button onClick={() => setConfirm(false)} className="px-3 py-1.5 border border-bw-border text-bw-muted rounded text-xs hover:text-bw-text transition-colors">Cancel</button>
              </div>
            ) : (
              <button onClick={() => setConfirm(true)}
                className="flex items-center gap-2 px-4 py-2 border border-bw-border rounded text-xs text-bw-muted hover:text-bw-white hover:border-bw-border2 transition-colors uppercase tracking-widest">
                <Trash2 size={13} /> Clear
              </button>
            )
          )}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2">
          {['ALL','MALICIOUS','SUSPICIOUS','CLEAN'].map(v => (
            <button key={v} onClick={() => setFilter(v)}
              className={`px-3 py-1 rounded text-[11px] tracking-widest uppercase border transition-colors
                ${filter === v ? 'border-bw-border2 text-bw-white bg-bw-card' : 'border-bw-border text-bw-muted hover:text-bw-text'}`}>
              {v} <span className="ml-1 text-bw-muted">{counts[v]}</span>
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="flex items-center gap-2 border border-bw-border rounded bg-bw-panel px-3 py-2 focus-within:border-bw-border2 transition-colors">
          <Search size={13} className="text-bw-muted flex-shrink-0" />
          <input type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search by file name or URL…"
            className="flex-1 bg-transparent text-bw-text placeholder-bw-muted text-xs outline-none" />
          {search && <button onClick={() => setSearch('')} className="text-bw-muted hover:text-bw-white transition-colors"><X size={13} /></button>}
        </div>

        {/* Table */}
        {filtered.length === 0 ? (
          <div className="border border-bw-border rounded-lg bg-bw-panel p-16 text-center">
            <Clock size={32} className="text-bw-border mx-auto mb-4" />
            <p className="text-bw-sub text-sm">
              {history.length === 0 ? 'No scans yet. Run your first analysis.' : 'No results match your filter.'}
            </p>
          </div>
        ) : (
          <div className="border border-bw-border rounded-lg overflow-hidden bg-bw-panel">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-bw-border bg-bw-card">
                    {['Target','Type / Engine','Verdict','Risk','Scanned At',''].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-[10px] text-bw-muted tracking-widest uppercase font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(r => <Row key={r.id} r={r} onView={setView} onDelete={handleDelete} />)}
                </tbody>
              </table>
            </div>
            <div className="px-4 py-2.5 border-t border-bw-border text-[10px] text-bw-muted">
              {filtered.length} of {history.length} records
            </div>
          </div>
        )}
      </div>

      {viewReport && <ThreatReport report={viewReport} onClose={() => setView(null)} />}
    </div>
  );
}
