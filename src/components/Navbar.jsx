import { Link, NavLink } from 'react-router-dom';
import { Shield, Activity, Clock, Menu, X } from 'lucide-react';
import { useState } from 'react';

const links = [
  { to: '/',        label: 'Home'    },
  { to: '/scan',    label: 'Scan'    },
  { to: '/history', label: 'History' },
];

export default function Navbar() {
  const [open, setOpen] = useState(false);

  return (
    <nav className="sticky top-0 z-50 border-b border-bw-border bg-bw-bg/95 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-14">

          <Link to="/" className="flex items-center gap-2.5">
            <Shield size={16} className="text-bw-white" />
            <span className="text-bw-white font-bold text-sm tracking-[0.2em] uppercase">Aegis</span>
            <span className="text-bw-muted text-[10px] tracking-widest hidden sm:block">/ Threat Analyzer</span>
          </Link>

          <div className="hidden md:flex items-center gap-1">
            {links.map(({ to, label }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                className={({ isActive }) =>
                  `px-4 py-1.5 text-xs tracking-widest uppercase transition-colors
                  ${isActive ? 'text-bw-white' : 'text-bw-sub hover:text-bw-text'}`
                }
              >
                {label}
              </NavLink>
            ))}
          </div>

          <div className="hidden md:flex items-center gap-1.5 text-[11px] text-bw-muted">
            <span className="w-1.5 h-1.5 rounded-full bg-bw-muted animate-pulse" />
            Online
          </div>

          <button
            className="md:hidden text-bw-sub hover:text-bw-white transition-colors"
            onClick={() => setOpen(!open)}
          >
            {open ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {open && (
        <div className="md:hidden border-t border-bw-border bg-bw-panel px-6 py-3 space-y-1">
          {links.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `block py-2 text-xs tracking-widest uppercase transition-colors
                ${isActive ? 'text-bw-white' : 'text-bw-sub hover:text-bw-text'}`
              }
            >
              {label}
            </NavLink>
          ))}
        </div>
      )}
    </nav>
  );
}
