import { CopyButton } from './CopyButton';

interface JWTColorizerProps {
  token: string;
}

function partColor(index: number): string {
  if (index === 0) return 'text-violet-700';
  if (index === 1) return 'text-teal-700';
  return 'text-orange-700';
}

function partHint(index: number): string {
  if (index === 0) return 'JOSE Header (Base64URL)';
  if (index === 1) return 'Claims (Base64URL)';
  return 'Signature (Base64URL)';
}

export function JWTColorizer({ token }: JWTColorizerProps) {
  const parts = token.split('.');

  if (parts.length !== 3) {
    return <p className="text-sm text-rose-600">Invalid JWT format: expected 3 segments.</p>;
  }

  return (
    <div className="space-y-3 rounded-xl border border-slate-200 bg-white p-4">
      <div className="break-all font-mono text-sm">
        {parts.map((part, index) => (
          <span key={`${index}-${part.slice(0, 8)}`}>
            <span title={partHint(index)} className={`cursor-pointer underline decoration-dotted ${partColor(index)}`}>
              {part}
            </span>
            {index < parts.length - 1 && <span className="px-1 text-slate-400">.</span>}
          </span>
        ))}
      </div>

      <div className="flex flex-wrap gap-2">
        {parts.map((part, index) => (
          <CopyButton key={`copy-${index}`} value={part} label={`Copy ${['Header', 'Payload', 'Signature'][index]}`} />
        ))}
      </div>
    </div>
  );
}
