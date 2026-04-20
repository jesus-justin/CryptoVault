interface KeyStrengthMeterProps {
  keyLength: number;
  algorithm: string;
}

type Strength = 'Weak' | 'Fair' | 'Strong' | 'Very Strong' | 'Excellent';

function evaluateStrength(keyLength: number, algorithm: string): { score: number; label: Strength } {
  const normalized = algorithm.toUpperCase();

  if (normalized.includes('RSA')) {
    if (keyLength < 2048) return { score: 1, label: 'Weak' };
    if (keyLength < 3072) return { score: 2, label: 'Fair' };
    if (keyLength < 4096) return { score: 3, label: 'Strong' };
    return { score: 5, label: 'Excellent' };
  }

  if (normalized.includes('AES')) {
    if (keyLength <= 128) return { score: 3, label: 'Strong' };
    if (keyLength <= 192) return { score: 4, label: 'Very Strong' };
    return { score: 5, label: 'Excellent' };
  }

  if (normalized.includes('P-256')) return { score: 3, label: 'Strong' };
  if (normalized.includes('P-384')) return { score: 4, label: 'Very Strong' };
  if (normalized.includes('P-521') || normalized.includes('ED25519')) return { score: 5, label: 'Excellent' };

  return { score: 2, label: 'Fair' };
}

const colors = ['bg-rose-500', 'bg-orange-500', 'bg-yellow-500', 'bg-lime-500', 'bg-emerald-500'];

export function KeyStrengthMeter({ keyLength, algorithm }: KeyStrengthMeterProps) {
  const { score, label } = evaluateStrength(keyLength, algorithm);

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-3">
      <div className="mb-2 flex items-center justify-between text-xs">
        <span className="font-semibold text-slate-700">Key Strength</span>
        <span className="text-slate-500">{label}</span>
      </div>

      <div className="grid grid-cols-5 gap-1">
        {colors.map((color, index) => (
          <span
            key={color}
            className={`h-2 rounded-full transition-opacity ${color} ${index < score ? 'opacity-100' : 'opacity-20'}`}
          />
        ))}
      </div>
    </div>
  );
}
