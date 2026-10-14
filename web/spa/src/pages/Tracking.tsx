import { useEffect, useState } from 'react';
import { getJson } from '../api/client';
import type { CustomsReceipt, TrackingEvent } from '../api/types';
import { checkCustomsReceipt } from '../receipts/receiptCheck';
import { shareDeliveryNote } from '../sharing/shareLinks';
import { loadRecentSearches, rememberSearch, type RecentSearch } from '../storage/recentSearches';
import { formatDate, t } from '../i18n';

interface TrackingResult {
  shipmentId: string;
  consignee: string;
  events: TrackingEvent[];
  shareKey: JsonWebKey | null;
  receipt: CustomsReceipt | null;
}

export function Tracking() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<TrackingResult | null>(null);
  const [recent, setRecent] = useState<RecentSearch[]>([]);
  const [note, setNote] = useState('');
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    void loadRecentSearches().then(setRecent);
  }, []);

  async function search(trackingNumber: string) {
    setNotice(null);
    try {
      const found = await getJson<TrackingResult>(`/v1/tracking/${encodeURIComponent(trackingNumber.trim().toUpperCase())}`);
      setResult(found);
      await rememberSearch({ trackingNumber, consignee: found.consignee, searchedAt: new Date().toISOString() });
      setRecent(await loadRecentSearches());
    } catch {
      setResult(null);
      setNotice(t('tracking.notFound'));
    }
  }

  async function share() {
    if (!result?.shareKey) return;
    const url = await shareDeliveryNote(result.shipmentId, result.shareKey, note);
    await navigator.clipboard.writeText(url);
    setNote('');
  }

  async function checkReceipt() {
    if (!result?.receipt) return;
    const authority = await getJson<{ spki: string; validUntil: string }>('/v1/customs/authority-key');
    const verdict = await checkCustomsReceipt(result.receipt, authority);
    setNotice(verdict === 'valid' ? t('tracking.receiptValid') : t('tracking.receiptInvalid'));
  }

  return (
    <main>
      <h1>{t('nav.tracking')}</h1>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void search(query);
        }}
      >
        <input aria-label={t('tracking.search')} list="recent-searches" value={query} onChange={(e) => setQuery(e.target.value)} />
        <datalist id="recent-searches">
          {recent.map((r) => (
            <option key={r.trackingNumber} value={r.trackingNumber}>
              {r.consignee}
            </option>
          ))}
        </datalist>
      </form>
      {notice && <p role="status">{notice}</p>}
      {result && (
        <section>
          <ol className="timeline">
            {result.events.map((event) => (
              <li key={event.at}>
                {formatDate(event.at)} · {t(`tracking.status.${event.status}` as Parameters<typeof t>[0])}
                {event.depot ? ` · ${event.depot}` : ''}
              </li>
            ))}
          </ol>
          {result.shareKey && (
            <div>
              <h2>{t('tracking.shareNote')}</h2>
              <p>{t('tracking.shareNoteHelp')}</p>
              <textarea value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} />
              <button type="button" onClick={() => void share()}>
                {t('tracking.shareNote')}
              </button>
            </div>
          )}
          {result.receipt && (
            <button type="button" onClick={() => void checkReceipt()}>
              {t('tracking.receipt')}
            </button>
          )}
        </section>
      )}
    </main>
  );
}
