// Business accounts release escrow only with an approver key (a passkey on a phone or
// security key). This component enrols one for the signed-in approver.
import { useState } from 'react';
import { postJson } from '../api/client';
import type { Account, ApproverKeyOptions } from '../api/types';
import { base64UrlToBytes, bytesToBase64Url, utf8 } from '../crypto/bytes';
import { t } from '../i18n';

type Status = 'idle' | 'working' | 'done' | 'failed';

interface Props {
  account: Account;
  options: ApproverKeyOptions;
  onEnrolled: () => void;
}

function creationBase(options: ApproverKeyOptions, account: Account) {
  return {
    challenge: base64UrlToBytes(options.challenge),
    rp: { id: options.rpId, name: 'Tallowbrook' },
    user: { id: utf8(account.id), name: account.email, displayName: account.name },
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' } as const,
    timeout: 120_000,
    attestation: 'none' as const,
  };
}

async function registerApproverKey(accountId: string, creation: CredentialCreationOptions['publicKey']): Promise<void> {
  const credential = (await navigator.credentials.create({ publicKey: creation })) as PublicKeyCredential | null;
  if (!credential) throw new Error('No credential was created');
  const response = credential.response as AuthenticatorAttestationResponse;
  await postJson(`/v1/accounts/${accountId}/approver-keys`, {
    id: credential.id,
    clientDataJSON: bytesToBase64Url(new Uint8Array(response.clientDataJSON)),
    attestationObject: bytesToBase64Url(new Uint8Array(response.attestationObject)),
    transports: response.getTransports?.() ?? [],
  });
}

export function EnrolApproverKey({ account, options, onEnrolled }: Props) {
  const [status, setStatus] = useState<Status>('idle');
  const enrol = () => {
    setStatus('working');
    registerApproverKey(account.id, creation).then(
      () => {
        setStatus('done');
        onEnrolled();
      },
      () => setStatus('failed'),
    );
  };
  if (!navigator.credentials) throw new Error('This browser cannot create passkeys');
  const creation: CredentialCreationOptions['publicKey'] = {
    ...creationBase(options, account),
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
      { type: 'public-key', alg: -8 },
    ],
  };
  return (
    <button type="button" aria-label="Register approver key" onClick={enrol} disabled={status === 'working'}>
      {status === 'failed' ? t('approvers.retry') : status === 'done' ? t('approvers.done') : t('approvers.register')}
    </button>
  );
}
