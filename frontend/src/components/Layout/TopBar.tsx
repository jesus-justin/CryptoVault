interface TopBarProps {
  requestId?: string;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
}

export function TopBar({ requestId, theme, onToggleTheme }: TopBarProps) {
  return (
    <header className="sticky top-0 z-20 flex items-center justify-between border-b border-slate-200 bg-white/80 px-6 py-4 backdrop-blur">
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-[0.2em] text-slate-500">Crypto Operations Console</h2>
        <p className="mt-1 text-xs text-slate-500">Request ID: {requestId ?? 'N/A'}</p>
      </div>

      <button
        type="button"
        onClick={onToggleTheme}
        className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-medium text-slate-700 transition hover:border-slate-900 hover:text-slate-900"
      >
        Theme: {theme === 'light' ? 'Light' : 'Dark'}
      </button>
    </header>
  );
}
