import { useState } from 'react';
import { ApiError, postJson } from '../api/client';
import type { Claim } from '../api/types';
import { photoProblem, uploadClaimPhoto } from '../uploads/claimPhotoUpload';
import { t } from '../i18n';

const REASONS: Claim['reason'][] = ['damaged', 'missing_items', 'not_delivered', 'late'];

export function Claims({ shipmentId }: { shipmentId: string }) {
  const [reason, setReason] = useState<Claim['reason']>('damaged');
  const [description, setDescription] = useState('');
  const [amount, setAmount] = useState('');
  const [claimId, setClaimId] = useState<string | null>(null);
  const [messages, setMessages] = useState<string[]>([]);

  const say = (text: string) => setMessages((list) => [...list, text]);

  async function open() {
    try {
      const created = await postJson<{ id: string }>('/v1/claims', {
        shipmentId,
        reason,
        description,
        amountMinor: Math.round(Number(amount) * 100),
      });
      setClaimId(created.id);
      say(t('claims.submitted'));
    } catch (err) {
      say(err instanceof ApiError ? Object.values(err.details ?? {}).join(', ') || err.code : t('errors.generic'));
    }
  }

  async function addPhotos(files: FileList | null) {
    if (!files || !claimId) return;
    for (const file of Array.from(files)) {
      const problem = photoProblem(file);
      if (problem) {
        say(problem);
        continue;
      }
      try {
        await uploadClaimPhoto(claimId, file);
        say(t('claims.photoUploaded'));
      } catch {
        say(t('claimPhotoChecksumMismatch'));
      }
    }
  }

  return (
    <main>
      <h1>{t('claims.new')}</h1>
      <label>
        {t('claims.reason')}
        <select value={reason} onChange={(e) => setReason(e.target.value as Claim['reason'])}>
          {REASONS.map((r) => (
            <option key={r} value={r}>
              {t(`claims.reason.${r}` as Parameters<typeof t>[0])}
            </option>
          ))}
        </select>
      </label>
      <label>
        {t('claims.description')}
        <textarea value={description} onChange={(e) => setDescription(e.target.value)} />
      </label>
      <label>
        {t('claims.amount')}
        <input inputMode="decimal" value={amount} onChange={(e) => setAmount(e.target.value)} />
      </label>
      <button type="button" disabled={claimId !== null} onClick={() => void open()}>
        {t('claims.new')}
      </button>
      {claimId && (
        <label>
          {t('claims.addPhotos')}
          <input type="file" accept="image/jpeg,image/png,image/heic" multiple onChange={(e) => void addPhotos(e.target.files)} />
        </label>
      )}
      <ul>
        {messages.map((m, i) => (
          <li key={i}>{m}</li>
        ))}
      </ul>
    </main>
  );
}
