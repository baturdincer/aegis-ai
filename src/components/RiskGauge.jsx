export function RiskGaugeContainer({ score, size = 130 }) {
  const r = 44;
  const circ = 2 * Math.PI * r;
  const clamp = Math.min(100, Math.max(0, score ?? 0));
  const offset = circ - (clamp / 100) * circ;

  const label =
    clamp >= 70 ? 'MALICIOUS' :
    clamp >= 40 ? 'SUSPICIOUS' :
    'CLEAN';

  // Monochrome: high risk = white, low risk = dim gray
  const strokeColor =
    clamp >= 70 ? '#ffffff' :
    clamp >= 40 ? '#888888' :
    '#444444';

  const textColor =
    clamp >= 70 ? '#ffffff' :
    clamp >= 40 ? '#888888' :
    '#555555';

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
        {/* Track */}
        <circle cx="50" cy="50" r={r} fill="none" stroke="#1a1a1a" strokeWidth="6" />
        {/* Value */}
        <circle
          cx="50" cy="50" r={r}
          fill="none"
          stroke={strokeColor}
          strokeWidth="6"
          strokeLinecap="butt"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1.2s ease-in-out, stroke 0.4s' }}
        />
      </svg>
      <div className="absolute flex flex-col items-center leading-none">
        <span className="text-2xl font-bold" style={{ color: textColor }}>{clamp}</span>
        <span className="text-[9px] tracking-widest mt-1" style={{ color: textColor }}>{label}</span>
      </div>
    </div>
  );
}

export default RiskGaugeContainer;
