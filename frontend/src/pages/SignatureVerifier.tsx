import { useState } from 'react';
import { useAsymmetricKeygen, useSign, useVerify } from '../hooks/useCrypto';

export default function SignatureVerifier() {
  const keygenMutation = useAsymmetricKeygen();
  const signMutation = useSign();
  const verifyMutation = useVerify();

  const [data, setData] = useState('message-to-sign');
  const [algorithm, setAlgorithm] = useState<'ECDSA-P384' | 'Ed25519'>('Ed25519');

  const keys = keygenMutation.data?.data as { publicKey: string; privateKey: string } | undefined;
  const signature = signMutation.data?.data as { signature: string } | undefined;

  const generateKeys = async () => {
    await keygenMutation.mutateAsync({ algorithm });
  };

  const signData = async () => {
    if (!keys) return;

    await signMutation.mutateAsync({
      algorithm,
      data,
      privateKey: keys.privateKey,
    });
  };

  const verifyData = async () => {
    if (!keys || !signature) return;

    await verifyMutation.mutateAsync({
      algorithm,
      data,
      signature: signature.signature,
      publicKey: keys.publicKey,
    });
  };

  return (
    <section className="space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-900">Signature Verifier</h1>

      <div className="space-y-3 rounded-2xl border border-slate-200 bg-white p-4">
        <select
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          value={algorithm}
          onChange={(event) => setAlgorithm(event.target.value as typeof algorithm)}
        >
          <option>Ed25519</option>
          <option>ECDSA-P384</option>
        </select>

        <textarea
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          rows={4}
          value={data}
          onChange={(event) => setData(event.target.value)}
        />

        <div className="flex gap-2">
          <button type="button" className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white" onClick={generateKeys}>
            Generate Keys
          </button>
          <button type="button" className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold" onClick={signData}>
            Sign
          </button>
          <button type="button" className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold" onClick={verifyData}>
            Verify
          </button>
        </div>

        {signature?.signature && <pre className="rounded-lg bg-slate-100 p-3 text-xs break-all">{signature.signature}</pre>}

        {verifyMutation.data?.data && (
          <pre className="rounded-lg bg-slate-100 p-3 text-sm">{JSON.stringify(verifyMutation.data.data, null, 2)}</pre>
        )}
      </div>
    </section>
  );
}
