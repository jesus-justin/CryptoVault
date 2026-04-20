import { useMemo, useState } from 'react';

interface HexViewerProps {
  data: string;
  encoding: 'base64' | 'hex' | 'utf8';
}

const BYTES_PER_ROW = 16;
const MAX_ROWS = 16;

function toBuffer(data: string, encoding: HexViewerProps['encoding']): Uint8Array {
  if (encoding === 'base64') {
    return Uint8Array.from(atob(data), (char) => char.charCodeAt(0));
  }

  if (encoding === 'hex') {
    const cleaned = data.replace(/\s+/g, '');
    const bytes = new Uint8Array(cleaned.length / 2);

    for (let i = 0; i < cleaned.length; i += 2) {
      bytes[i / 2] = Number.parseInt(cleaned.slice(i, i + 2), 16);
    }

    return bytes;
  }

  return new TextEncoder().encode(data);
}

function printable(byte: number): string {
  if (byte >= 32 && byte <= 126) {
    return String.fromCharCode(byte);
  }

  return '·';
}

export function HexViewer({ data, encoding }: HexViewerProps) {
  const [showAll, setShowAll] = useState(false);

  const bytes = useMemo(() => toBuffer(data, encoding), [data, encoding]);
  const rowCount = Math.ceil(bytes.length / BYTES_PER_ROW);
  const visibleRows = showAll ? rowCount : Math.min(rowCount, MAX_ROWS);

  return (
    <div className="rounded-xl border border-slate-200 bg-slate-950 p-4 font-mono text-xs text-slate-200">
      <div className="space-y-1 overflow-auto">
        {Array.from({ length: visibleRows }).map((_, rowIndex) => {
          const offset = rowIndex * BYTES_PER_ROW;
          const row = bytes.slice(offset, offset + BYTES_PER_ROW);
          const hex = Array.from(row)
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join(' ')
            .padEnd(BYTES_PER_ROW * 3 - 1, ' ');
          const ascii = Array.from(row)
            .map((byte) => printable(byte))
            .join('');

          return (
            <div key={offset} className="grid grid-cols-[70px_1fr_180px] gap-4">
              <span className="text-cyan-400">{offset.toString(16).padStart(8, '0')}</span>
              <span>{hex}</span>
              <span className="text-slate-400">{ascii}</span>
            </div>
          );
        })}
      </div>

      {!showAll && rowCount > MAX_ROWS && (
        <button
          type="button"
          className="mt-3 rounded-md border border-slate-700 px-3 py-1 text-xs hover:bg-slate-900"
          onClick={() => setShowAll(true)}
        >
          Show full output
        </button>
      )}
    </div>
  );
}
