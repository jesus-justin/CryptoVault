import { ChangeEvent, useState } from 'react';
import { useSymmetricDecrypt, useSymmetricEncrypt } from '../hooks/useCrypto';

export default function FileEncryptor() {
  const encryptMutation = useSymmetricEncrypt();
  const decryptMutation = useSymmetricDecrypt();

  const [fileContent, setFileContent] = useState('');
  const [passphrase, setPassphrase] = useState('file-passphrase');

  const encrypted = encryptMutation.data?.data as
    | {
        ciphertext: string;
        iv?: string;
        authTag?: string;
      }
    | undefined;

  const onFileChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    const text = await file.text();
    setFileContent(text);
  };

  const encrypt = async () => {
    await encryptMutation.mutateAsync({
      plaintext: fileContent,
      algorithm: 'AES-256-GCM',
      passphrase,
    });
  };

  const decrypt = async () => {
    if (!encrypted) {
      return;
    }

    await decryptMutation.mutateAsync({
      ciphertext: encrypted.ciphertext,
      algorithm: 'AES-256-GCM',
      passphrase,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
    });
  };

  return (
    <section className="space-y-6 p-6">
      <h1 className="text-2xl font-bold text-slate-900">File Encryptor</h1>

      <div className="space-y-4 rounded-2xl border border-slate-200 bg-white p-4">
        <input type="file" onChange={onFileChange} className="text-sm" />
        <input
          className="w-full rounded-xl border border-slate-300 px-3 py-2"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
          placeholder="Passphrase"
        />

        <div className="flex gap-2">
          <button type="button" className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white" onClick={encrypt}>
            Encrypt File Content
          </button>
          <button type="button" className="rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold" onClick={decrypt}>
            Decrypt
          </button>
        </div>

        {encrypted?.ciphertext && (
          <pre className="max-h-40 overflow-auto rounded-lg bg-slate-950 p-3 text-xs text-slate-100">{encrypted.ciphertext}</pre>
        )}

        {decryptMutation.data?.data && (
          <pre className="max-h-40 overflow-auto rounded-lg bg-slate-100 p-3 text-xs text-slate-900">
            {(decryptMutation.data.data as { plaintext: string }).plaintext}
          </pre>
        )}
      </div>
    </section>
  );
}
