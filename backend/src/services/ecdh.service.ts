import {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
} from 'crypto';
import { ApiError } from '../types/api.types';
import { ECDHKeyPair, FullExchangeDemoResult, SharedSecretResult } from '../types/crypto.types';
import { timingSafeCompare } from '../utils/timingSafe';
import { zeroBuffer } from '../utils/zeroBuffer';

const ECDH_CONTEXT_INFO = 'CryptoVault-ECDH-v2';

class EcdhService {
  /**
   * @description Generates an X25519 key pair for ECDH key exchange.
   * @algorithm X25519
   * @reference RFC 7748
   * @security Keys are generated with Node.js crypto and exported in PEM format.
   * @param None.
   * @returns X25519 public/private key pair in PEM format.
   */
  generateKeyPair(): ECDHKeyPair {
    try {
      const { publicKey, privateKey } = generateKeyPairSync('x25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      return {
        publicKey,
        privateKey,
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'ECDH_KEYGEN_FAILED', 'Failed to generate X25519 key pair.', error);
    }
  }

  /**
   * @description Computes X25519 shared secret and derives a 32-byte key with HKDF-SHA256.
   * @algorithm X25519 + HKDF-SHA256
   * @reference RFC 7748; RFC 5869
   * @security Raw shared secret is zeroed immediately after derivation; raw secret return is educational only.
   * @param myPrivateKeyPem Local private key in PEM format.
   * @param theirPublicKeyPem Peer public key in PEM format.
   * @returns Raw shared secret (hex) and HKDF-derived key (base64).
   */
  computeSharedSecret(myPrivateKeyPem: string, theirPublicKeyPem: string): SharedSecretResult {
    let rawSecret: Buffer | undefined;
    let derivedKey: Buffer | undefined;

    try {
      const myPrivateKey = createPrivateKey(myPrivateKeyPem);
      const theirPublicKey = createPublicKey(theirPublicKeyPem);

      rawSecret = diffieHellman({
        privateKey: myPrivateKey,
        publicKey: theirPublicKey,
      });

      const rawSecretHex = rawSecret.toString('hex');
      const hkdfResult = hkdfSync(
        'sha256',
        rawSecret,
        Buffer.alloc(0),
        ECDH_CONTEXT_INFO,
        32,
      );
      derivedKey = Buffer.from(hkdfResult);

      return {
        sharedSecret: rawSecretHex,
        derivedKey: derivedKey.toString('base64'),
        algorithm: 'X25519',
      };
    } catch (error: unknown) {
      throw new ApiError(400, 'ECDH_EXCHANGE_FAILED', 'Failed to compute X25519 shared secret.', error);
    } finally {
      if (rawSecret) {
        zeroBuffer(rawSecret);
      }

      if (derivedKey) {
        zeroBuffer(derivedKey);
      }
    }
  }

  /**
   * @description Runs a full Alice/Bob ECDH exchange demo and validates derived key equality.
   * @algorithm X25519 + HKDF-SHA256
   * @reference RFC 7748; RFC 5869
   * @security Match check uses timing-safe comparison semantics.
   * @param None.
   * @returns Full exchange demo payload including both sides and match status.
   */
  fullExchangeDemo(): FullExchangeDemoResult {
    const alice = this.generateKeyPair();
    const bob = this.generateKeyPair();

    const aliceSecret = this.computeSharedSecret(alice.privateKey, bob.publicKey);
    const bobSecret = this.computeSharedSecret(bob.privateKey, alice.publicKey);

    const aliceDerived = Buffer.from(aliceSecret.derivedKey, 'base64');
    const bobDerived = Buffer.from(bobSecret.derivedKey, 'base64');

    try {
      const match = timingSafeCompare(aliceDerived, bobDerived);

      return {
        alice,
        bob,
        aliceSecret,
        bobSecret,
        match,
      };
    } finally {
      zeroBuffer(aliceDerived);
      zeroBuffer(bobDerived);
    }
  }
}

export const ecdhService = new EcdhService();
