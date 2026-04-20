import { useState } from 'react';

interface SecurityWarningProps {
  algorithm: string;
  reason: string;
  alternative: string;
}

export function SecurityWarning({ algorithm, reason, alternative }: SecurityWarningProps) {
  const [visible, setVisible] = useState(true);

  if (!visible) {
    return null;
  }

  return (
    <div className="flex items-start justify-between gap-3 rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-amber-900">
      <div>
        <p className="text-sm font-semibold">Security warning: {algorithm}</p>
        <p className="mt-1 text-sm">{reason}</p>
        <p className="mt-1 text-sm font-medium">Consider: {alternative}</p>
      </div>

      <button
        type="button"
        onClick={() => setVisible(false)}
        className="rounded-md border border-amber-400 px-2 py-1 text-xs font-semibold hover:bg-amber-100"
        aria-label="Dismiss warning"
      >
        X
      </button>
    </div>
  );
}
