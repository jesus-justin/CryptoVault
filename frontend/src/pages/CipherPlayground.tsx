import { FormEvent, useState } from 'react';
import { SecurityWarning } from '../components/ui/SecurityWarning';
import { useSymmetricDecrypt, useSymmetricEncrypt } from '../hooks/useCrypto';

export default function CipherPlayground() {
  const encryptMutation = useSymmetricEncrypt();
  const decryptMutation = useSymmetricDecrypt();

  const [plaintext, setPlaintext] = useState('Hello, CryptoVault');
  const [passphrase, setPassphrase] = useState('strong-passphrase');
  const [algorithm, setAlgorithm] = useState<'AES-256-GCM' | 'ChaCha20-Poly1305' | 'AES-256-CBC'>('AES-256-GCM');

  const encrypted = encryptMutation.data?.data as
    | {
        ciphertext: string;
        iv?: string;
        nonce?: string;
        authTag?: string;
        warning?: string;
      }
    | undefined;

  const handleEncrypt = async (event: FormEvent) => {
    event.preventDefault();
    await encryptMutation.mutateAsync({ plaintext, passphrase, algorithm });
  };

  const handleDecrypt = async () => {
    if (!encrypted) {
      return;
    }

    await decryptMutation.mutateAsync({
      ciphertext: encrypted.ciphertext,
      algorithm,
      passphrase,
      iv: encrypted.iv,
      nonce: encrypted.nonce,
      authTag: encrypted.authTag,
    });
  };

  return (
    <section className="space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-900">Cipher Playground</h1>

      {algorithm === 'AES-256-CBC' && (
        <SecurityWarning
          algorithm="AES-256-CBC"
          reason="AES-256-CBC has no authentication tag."
          alternative="AES-256-GCM"
        />
      )}

      <form onSubmit={handleEncrypt} className="space-y-4 rounded-2xl border border-slate-200 bg-white p-4">
        <textarea
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          rows={4}
          value={plaintext}
          onChange={(event) => setPlaintext(event.target.value)}
        />

        <input
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
          placeholder="Passphrase"
        />

        <select
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          value={algorithm}
          onChange={(event) => setAlgorithm(event.target.value as typeof algorithm)}
        >
          <option>AES-256-GCM</option>
          <option>ChaCha20-Poly1305</option>
          <option>AES-256-CBC</option>
        </select>

        <button type="submit" className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white">
          Encrypt
        </button>
      </form>

      {encrypted && (
        <div className="space-y-3 rounded-2xl border border-slate-200 bg-white p-4 text-sm">
          <p className="break-all"><strong>Ciphertext:</strong> {encrypted.ciphertext}</p>
          {encrypted.iv && <p className="break-all"><strong>IV:</strong> {encrypted.iv}</p>}
          {encrypted.nonce && <p className="break-all"><strong>Nonce:</strong> {encrypted.nonce}</p>}
          {encrypted.authTag && <p className="break-all"><strong>AuthTag:</strong> {encrypted.authTag}</p>}
          {encrypted.warning && <p className="text-amber-700">{encrypted.warning}</p>}
          <button
            type="button"
            onClick={handleDecrypt}
            className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold"
          >
            Decrypt
          </button>
          {decryptMutation.data?.data && (
            <p className="break-all"><strong>Plaintext:</strong> {(decryptMutation.data.data as { plaintext: string }).plaintext}</p>
          )}
        </div>
      )}
    </section>
  );
}
