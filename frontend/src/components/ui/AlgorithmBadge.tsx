interface AlgorithmBadgeProps {
  algorithm: string;
  status: 'recommended' | 'legacy' | 'deprecated' | 'experimental';
}

const statusConfig = {
  recommended: {
    label: 'Recommended',
    classes: 'bg-emerald-100 text-emerald-800 border-emerald-200',
    reason: 'Modern, secure default for production use.',
    icon: '✓',
  },
  legacy: {
    label: 'Legacy',
    classes: 'bg-amber-100 text-amber-900 border-amber-200',
    reason: 'Supported for compatibility but not recommended for new systems.',
    icon: '⚠',
  },
  deprecated: {
    label: 'Deprecated',
    classes: 'bg-rose-100 text-rose-800 border-rose-200',
    reason: 'Known weaknesses; avoid in security-sensitive workflows.',
    icon: '✕',
  },
  experimental: {
    label: 'Experimental',
    classes: 'bg-sky-100 text-sky-800 border-sky-200',
    reason: 'Limited maturity and compatibility.',
    icon: '⊕',
  },
} as const;

export function AlgorithmBadge({ algorithm, status }: AlgorithmBadgeProps) {
  const config = statusConfig[status];

  return (
    <span
      title={`${algorithm}: ${config.reason}`}
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-semibold ${config.classes}`}
    >
      <span>{config.icon}</span>
      <span>{algorithm}</span>
      <span className="opacity-70">({config.label})</span>
    </span>
  );
}
