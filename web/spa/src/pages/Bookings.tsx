import { useEffect, useState } from 'react';
import { ApiError, getJson, postJson } from '../api/client';
import type { Address, BookingDraft, ShipmentSummary } from '../api/types';
import { draftKeyFromPin, pinIsAcceptable } from '../crypto/pinKeys';
import { listDraftIds, loadDraft, saveDraft } from '../drafts/draftVault';
import { formatDate, t } from '../i18n';

const emptyAddress: Address = { name: '', street: '', city: '', postcode: '', country: 'GB' };

const emptyDraft = (): BookingDraft => ({
  service: 'standard',
  sender: { ...emptyAddress },
  consignee: { ...emptyAddress },
  parcels: [{ weightGrams: 1000, lengthCm: 30, widthCm: 20, heightCm: 10 }],
});

function AddressFields({ label, value, onChange }: { label: string; value: Address; onChange: (a: Address) => void }) {
  const field = (name: keyof Address) => (
    <label>
      {name}
      <input value={value[name] ?? ''} onChange={(e) => onChange({ ...value, [name]: e.target.value })} />
    </label>
  );
  return (
    <fieldset>
      <legend>{label}</legend>
      {field('name')}
      {field('street')}
      {field('city')}
      {field('postcode')}
      {field('country')}
    </fieldset>
  );
}

export function Bookings() {
  const [shipments, setShipments] = useState<ShipmentSummary[]>([]);
  const [draft, setDraft] = useState<BookingDraft>(emptyDraft);
  const [pin, setPin] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    getJson<{ items: ShipmentSummary[] }>('/v1/shipments').then(
      (page) => setShipments(page.items),
      () => setMessage(t('errors.offline')),
    );
  }, []);

  async function keepDraft() {
    if (!pinIsAcceptable(pin)) {
      setMessage(t('bookings.draftPinHelp'));
      return;
    }
    const key = await draftKeyFromPin(pin);
    await saveDraft(key, `d${Date.now()}`, draft);
    setMessage(t('bookings.draftSaved'));
  }

  async function reopenLatestDraft() {
    const ids = listDraftIds();
    if (ids.length === 0 || !pinIsAcceptable(pin)) return;
    const restored = await loadDraft(await draftKeyFromPin(pin), ids[ids.length - 1]);
    if (restored) setDraft(restored);
  }

  async function submit() {
    try {
      const created = await postJson<{ id: string; publicId: string }>('/v1/shipments', draft);
      setShipments((list) => [
        {
          _id: created.id,
          publicId: created.publicId,
          status: 'booked',
          service: draft.service,
          consignee: draft.consignee,
          createdAt: new Date().toISOString(),
        },
        ...list,
      ]);
      setDraft(emptyDraft());
      setErrors({});
    } catch (err) {
      if (err instanceof ApiError && err.details) setErrors(err.details);
      else setMessage(t('errors.generic'));
    }
  }

  return (
    <main>
      <h1>{t('nav.bookings')}</h1>
      {message && <p role="status">{message}</p>}
      <section>
        <h2>{t('bookings.new')}</h2>
        <select value={draft.service} onChange={(e) => setDraft({ ...draft, service: e.target.value as BookingDraft['service'] })}>
          <option value="standard">{t('bookings.service.standard')}</option>
          <option value="express">{t('bookings.service.express')}</option>
          <option value="economy">{t('bookings.service.economy')}</option>
        </select>
        <AddressFields label="Sender" value={draft.sender} onChange={(sender) => setDraft({ ...draft, sender })} />
        <AddressFields label="Consignee" value={draft.consignee} onChange={(consignee) => setDraft({ ...draft, consignee })} />
        {Object.entries(errors).map(([field, problem]) => (
          <p key={field} className="field-error">
            {field}: {problem}
          </p>
        ))}
        <label>
          {t('bookings.draftPin')}
          <input inputMode="numeric" value={pin} onChange={(e) => setPin(e.target.value)} onBlur={() => void reopenLatestDraft()} />
        </label>
        <button type="button" onClick={() => void keepDraft()}>
          {t('bookings.saveDraft')}
        </button>
        <button type="button" onClick={() => void submit()}>
          {t('bookings.submit')}
        </button>
      </section>
      <section>
        {shipments.length === 0 ? (
          <p>{t('bookings.empty')}</p>
        ) : (
          <table>
            <tbody>
              {shipments.map((s) => (
                <tr key={s._id}>
                  <td>{s.publicId}</td>
                  <td>{s.consignee.name}</td>
                  <td>{t(`tracking.status.${s.status}` as Parameters<typeof t>[0])}</td>
                  <td>{formatDate(s.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}
