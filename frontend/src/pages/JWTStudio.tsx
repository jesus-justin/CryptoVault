import { FormEvent, useState } from 'react';
import { JWTColorizer } from '../components/ui/JWTColorizer';
import { useJwtDecode, useJwtSign, useJwtVerify, useJweCreate } from '../hooks/useCrypto';

export default function JWTStudio() {
  const signMutation = useJwtSign();
  const verifyMutation = useJwtVerify();
  const decodeMutation = useJwtDecode();
  const jweMutation = useJweCreate();

  const [secret, setSecret] = useState('x'.repeat(64));
  const [token, setToken] = useState('');

  const handleSign = async (event: FormEvent) => {
    event.preventDefault();
    const result = await signMutation.mutateAsync({
      payload: { sub: 'user-123', role: 'admin' },
      algorithm: 'HS256',
      secretOrPrivateKey: secret,
      expiresIn: '1h',
    });

    const signed = result.data as { token: string };
    setToken(signed.token);
  };

  const handleVerify = async () => {
    if (!token) {
      return;
    }

    await verifyMutation.mutateAsync({ token, algorithm: 'HS256', secretOrPublicKey: secret });
  };

  const handleDecode = async () => {
    if (!token) {
      return;
    }

    await decodeMutation.mutateAsync({ token });
  };

  const handleJwe = async () => {
    const publicKey = [
      '-----BEGIN PUBLIC KEY-----',
      'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL5j2rEB5M6QXHkD1E6i9Qf6mMtN5k7E',
      '3M1iXvYfQp8X37q4G6mJ9N7s8YhYkFQh9Kk6a2wYqY9J2n5q+7p8J8ECAwEAAQ==',
      '-----END PUBLIC KEY-----',
    ].join('\n');

    await jweMutation.mutateAsync({ payload: { demo: true }, publicKey });
  };

  return (
    <section className="space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-900">JWT Studio</h1>

      <form onSubmit={handleSign} className="space-y-3 rounded-2xl border border-slate-200 bg-white p-4">
        <textarea
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          rows={3}
          value={secret}
          onChange={(event) => setSecret(event.target.value)}
        />

        <div className="flex flex-wrap gap-2">
          <button type="submit" className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white">
            Sign HS256
          </button>
          <button type="button" onClick={handleVerify} className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold">
            Verify
          </button>
          <button type="button" onClick={handleDecode} className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold">
            Decode
          </button>
          <button type="button" onClick={handleJwe} className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold">
            Create JWE
          </button>
        </div>
      </form>

      {token && <JWTColorizer token={token} />}

      {verifyMutation.data?.data && (
        <pre className="rounded-xl bg-slate-100 p-3 text-sm">{JSON.stringify(verifyMutation.data.data, null, 2)}</pre>
      )}

      {decodeMutation.data?.data && (
        <pre className="rounded-xl bg-slate-100 p-3 text-sm">{JSON.stringify(decodeMutation.data.data, null, 2)}</pre>
      )}

      {jweMutation.data?.data && (
        <pre className="rounded-xl bg-slate-950 p-3 text-xs text-slate-100 break-all">
          {JSON.stringify(jweMutation.data.data, null, 2)}
        </pre>
      )}
    </section>
  );
}
