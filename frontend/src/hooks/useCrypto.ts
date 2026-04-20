import { useMutation, UseMutationResult } from '@tanstack/react-query';
import { postApi } from '../lib/api';
import {
  AsymmetricKeygenInput,
  AvalancheInput,
  HashInput,
  HmacInput,
  JwtDecodeInput,
  JwtSignInput,
  JwtVerifyInput,
  JweInput,
  KdfDeriveInput,
  KdfVerifyInput,
  SignInput,
  SymmetricDecryptInput,
  SymmetricEncryptInput,
  VerifyInput,
  EcdhExchangeInput,
} from '../lib/schemas';

export interface MutationErrorShape {
  code: string;
  message: string;
  field?: string;
}

interface ApiEnvelope<TData> {
  success: boolean;
  data: TData | null;
  error: string | null;
  requestId: string;
  timestamp: string;
}

function createMutation<TInput, TData>(url: string): UseMutationResult<ApiEnvelope<TData>, MutationErrorShape, TInput> {
  return useMutation<ApiEnvelope<TData>, MutationErrorShape, TInput>({
    mutationFn: async (input: TInput) => postApi<ApiEnvelope<TData>, TInput>(url, input),
    onError: () => {
      // Errors are normalized in api.ts interceptor.
    },
  });
}

export function useSymmetricEncrypt() {
  return createMutation<SymmetricEncryptInput, Record<string, unknown>>('/symmetric/encrypt');
}

export function useSymmetricDecrypt() {
  return createMutation<SymmetricDecryptInput, Record<string, unknown>>('/symmetric/decrypt');
}

export function useAsymmetricKeygen() {
  return createMutation<AsymmetricKeygenInput, Record<string, unknown>>('/asymmetric/keygen');
}

export function useSign() {
  return createMutation<SignInput, Record<string, unknown>>('/asymmetric/sign');
}

export function useVerify() {
  return createMutation<VerifyInput, Record<string, unknown>>('/asymmetric/verify');
}

export function useHash() {
  return createMutation<HashInput, Record<string, unknown>>('/hash');
}

export function useHmac() {
  return createMutation<HmacInput, Record<string, unknown>>('/hash/hmac');
}

export function useAvalanche() {
  return createMutation<AvalancheInput, Record<string, unknown>>('/hash/avalanche');
}

export function useKdfDerive() {
  return createMutation<KdfDeriveInput, Record<string, unknown>>('/kdf/derive');
}

export function useKdfVerify() {
  return createMutation<KdfVerifyInput, Record<string, unknown>>('/kdf/verify');
}

export function useJwtSign() {
  return createMutation<JwtSignInput, Record<string, unknown>>('/jwt/sign');
}

export function useJwtVerify() {
  return createMutation<JwtVerifyInput, Record<string, unknown>>('/jwt/verify');
}

export function useJwtDecode() {
  return createMutation<JwtDecodeInput, Record<string, unknown>>('/jwt/decode');
}

export function useJweCreate() {
  return createMutation<JweInput, Record<string, unknown>>('/jwt/jwe');
}

export function useEcdhExchange() {
  return createMutation<EcdhExchangeInput, Record<string, unknown>>('/ecdh/exchange');
}
