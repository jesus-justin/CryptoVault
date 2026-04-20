import { useState } from 'react';
import { CopyButton } from '../components/ui/CopyButton';
import { KeyStrengthMeter } from '../components/ui/KeyStrengthMeter';
import { useAsymmetricKeygen } from '../hooks/useCrypto';

export default function KeyManager() {
  const keygenMutation = useAsymmetricKeygen();
  const [algorithm, setAlgorithm] = useState<'RSA-4096' | 'ECDSA-P384' | 'Ed25519'>('RSA-4096');

  const keyData = keygenMutation.data?.data as
    | {
        publicKey: string;
        privateKey: string;
      }
    | undefined;

  const keyLength = algorithm === 'RSA-4096' ? 4096 : algorithm === 'ECDSA-P384' ? 384 : 255;

  return (
    <section className="space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-900">Key Manager</h1>

      <div className="space-y-4 rounded-2xl border border-slate-200 bg-white p-4">
        <select
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          value={algorithm}
          onChange={(event) => setAlgorithm(event.target.value as typeof algorithm)}
        >
          <option>RSA-4096</option>
          <option>ECDSA-P384</option>
          <option>Ed25519</option>
        </select>

        <KeyStrengthMeter keyLength={keyLength} algorithm={algorithm} />

        <button
          type="button"
          className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white"
          onClick={() => keygenMutation.mutate({ algorithm })}
        >
          Generate Key Pair
        </button>

        {keyData && (
          <div className="space-y-3 text-sm">
            <div className="rounded-lg border border-slate-200 p-3">
              <div className="mb-2 flex items-center justify-between">
                <strong>Public Key</strong>
                <CopyButton value={keyData.publicKey} />
              </div>
              <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all">{keyData.publicKey}</pre>
            </div>

            <div className="rounded-lg border border-slate-200 p-3">
              <div className="mb-2 flex items-center justify-between">
                <strong>Private Key</strong>
                <CopyButton value={keyData.privateKey} />
              </div>
              <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all">{keyData.privateKey}</pre>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
