import { FormEvent, useState } from 'react';
import { HexViewer } from '../components/ui/HexViewer';
import { SecurityWarning } from '../components/ui/SecurityWarning';
import { useAvalanche, useHash, useHmac } from '../hooks/useCrypto';

export default function HashAnalyzer() {
  const hashMutation = useHash();
  const hmacMutation = useHmac();
  const avalancheMutation = useAvalanche();

  const [input, setInput] = useState('abc');
  const [algorithm, setAlgorithm] = useState<'sha256' | 'sha512' | 'sha3-256' | 'sha3-512' | 'md5'>('sha256');

  const handleHash = async (event: FormEvent) => {
    event.preventDefault();
    await hashMutation.mutateAsync({ input, algorithm });
  };

  const handleHmac = async () => {
    await hmacMutation.mutateAsync({ input, key: 'shared-secret', algorithm: 'sha256' });
  };

  const handleAvalanche = async () => {
    await avalancheMutation.mutateAsync({ input, algorithm: 'sha256' });
  };

  const hashResult = hashMutation.data?.data as { hash: string; warning?: string } | undefined;

  return (
    <section className="space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-900">Hash Analyzer</h1>

      {algorithm === 'md5' && (
        <SecurityWarning
          algorithm="MD5"
          reason="MD5 is cryptographically broken and vulnerable to collisions."
          alternative="SHA-256 or SHA3-256"
        />
      )}

      <form onSubmit={handleHash} className="space-y-3 rounded-2xl border border-slate-200 bg-white p-4">
        <textarea
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          rows={4}
        />
        <select
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          value={algorithm}
          onChange={(event) => setAlgorithm(event.target.value as typeof algorithm)}
        >
          <option value="sha256">SHA-256</option>
          <option value="sha512">SHA-512</option>
          <option value="sha3-256">SHA3-256</option>
          <option value="sha3-512">SHA3-512</option>
          <option value="md5">MD5 (Educational)</option>
        </select>

        <div className="flex flex-wrap gap-2">
          <button type="submit" className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white">
            Hash
          </button>
          <button
            type="button"
            onClick={handleHmac}
            className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold"
          >
            HMAC-SHA256
          </button>
          <button
            type="button"
            onClick={handleAvalanche}
            className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold"
          >
            Avalanche Test
          </button>
        </div>
      </form>

      {hashResult?.hash && <HexViewer data={hashResult.hash} encoding="hex" />}

      {hashResult?.warning && <p className="text-sm font-medium text-amber-700">{hashResult.warning}</p>}
      {hmacMutation.data?.data && (
        <p className="rounded-lg bg-slate-100 p-3 text-sm break-all">HMAC: {(hmacMutation.data.data as { hmac: string }).hmac}</p>
      )}
      {avalancheMutation.data?.data && (
        <p className="rounded-lg bg-slate-100 p-3 text-sm">
          Avalanche change: {(avalancheMutation.data.data as { percentage: number }).percentage.toFixed(2)}%
        </p>
      )}
    </section>
  );
}
