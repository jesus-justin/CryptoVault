import { useState } from 'react';
import { postApi } from '../lib/api';
import { useEcdhExchange } from '../hooks/useCrypto';

interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export default function KeyExchangeLab() {
  const exchangeMutation = useEcdhExchange();
  const [alice, setAlice] = useState<KeyPair | null>(null);
  const [bob, setBob] = useState<KeyPair | null>(null);

  const generateKeyPair = async (): Promise<KeyPair> => {
    const response = await postApi<{
      success: boolean;
      data: KeyPair;
    }, Record<string, never>>('/ecdh/keygen', {});

    return response.data;
  };

  const runDemo = async () => {
    const generatedAlice = await generateKeyPair();
    const generatedBob = await generateKeyPair();

    setAlice(generatedAlice);
    setBob(generatedBob);

    await exchangeMutation.mutateAsync({
      myPrivateKey: generatedAlice.privateKey,
      theirPublicKey: generatedBob.publicKey,
    });
  };

  return (
    <section className="space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-900">Key Exchange Lab</h1>

      <div className="rounded-2xl border border-slate-200 bg-white p-4">
        <button
          type="button"
          className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white"
          onClick={runDemo}
        >
          Run X25519 Exchange
        </button>

        {alice && bob && (
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-slate-200 p-3">
              <p className="text-sm font-semibold">Alice Public Key</p>
              <pre className="max-h-32 overflow-auto text-xs">{alice.publicKey}</pre>
            </div>

            <div className="rounded-lg border border-slate-200 p-3">
              <p className="text-sm font-semibold">Bob Public Key</p>
              <pre className="max-h-32 overflow-auto text-xs">{bob.publicKey}</pre>
            </div>
          </div>
        )}

        {exchangeMutation.data?.data && (
          <pre className="mt-4 rounded-lg bg-slate-100 p-3 text-xs break-all">
            {JSON.stringify(exchangeMutation.data.data, null, 2)}
          </pre>
        )}
      </div>
    </section>
  );
}
