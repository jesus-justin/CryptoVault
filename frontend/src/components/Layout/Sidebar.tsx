import { NavLink } from 'react-router-dom';

const items = [
  { to: '/', label: 'Dashboard', icon: '◉' },
  { to: '/cipher-playground', label: 'Cipher Playground', icon: '⬢' },
  { to: '/key-manager', label: 'Key Manager', icon: '◆' },
  { to: '/hash-analyzer', label: 'Hash Analyzer', icon: '◈' },
  { to: '/file-encryptor', label: 'File Encryptor', icon: '▣' },
  { to: '/jwt-studio', label: 'JWT Studio', icon: '◎' },
  { to: '/signature-verifier', label: 'Signature Verifier', icon: '✦' },
  { to: '/key-exchange-lab', label: 'Key Exchange Lab', icon: '⟲' },
];

export function Sidebar() {
  return (
    <aside className="w-full border-b border-slate-200 bg-white/80 p-4 backdrop-blur md:h-screen md:w-72 md:border-b-0 md:border-r">
      <div className="mb-4 px-3">
        <h1 className="text-lg font-bold tracking-wide text-slate-900">CryptoVault v2</h1>
        <p className="text-xs text-slate-600">Enterprise Cryptography System</p>
      </div>

      <nav className="grid gap-1">
        {items.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              [
                'flex items-center gap-3 rounded-xl px-3 py-2 text-sm transition-colors',
                isActive
                  ? 'bg-slate-900 text-white shadow-md'
                  : 'text-slate-700 hover:bg-slate-100 hover:text-slate-900',
              ].join(' ')
            }
          >
            <span className="text-base">{item.icon}</span>
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
