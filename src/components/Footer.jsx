import { Shield } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="mt-auto border-t border-bw-border py-5 px-6">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] text-bw-muted">
        <div className="flex items-center gap-2">
          <Shield size={12} className="text-bw-sub" />
          <span className="tracking-widest uppercase">Aegis Threat Analyzer</span>
          <span className="text-bw-border">—</span>
          <span>Academic Project</span>
        </div>
        <span>&copy; {new Date().getFullYear()}</span>
      </div>
    </footer>
  );
}
