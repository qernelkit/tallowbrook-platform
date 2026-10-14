import { useEffect, useState } from 'react';
import { getJson } from './api/client';
import type { Account } from './api/types';
import { sendPageView } from './analytics/beacon';
import { Bookings } from './pages/Bookings';
import { Claims } from './pages/Claims';
import { DriverTraining, Settings } from './pages/Settings';
import { Tracking } from './pages/Tracking';
import { t } from './i18n';

type Page = 'bookings' | 'tracking' | 'claims' | 'settings';

function sessionId(): string {
  let id = sessionStorage.getItem('tb.sid');
  if (!id) {
    id = crypto.randomUUID();
    sessionStorage.setItem('tb.sid', id);
  }
  return id;
}

export function App() {
  const [page, setPage] = useState<Page>('bookings');
  const [account, setAccount] = useState<Account | null>(null);
  const [openedAt, setOpenedAt] = useState(Date.now());
  const params = new URLSearchParams(window.location.search);

  useEffect(() => {
    getJson<Account>('/v1/account/me').then(setAccount, () => setAccount(null));
  }, []);

  useEffect(() => {
    const started = openedAt;
    return () =>
      sendPageView(sessionId(), {
        path: `/${page}`,
        referrer: document.referrer,
        durationMs: Date.now() - started,
        viewport: `${window.innerWidth}x${window.innerHeight}`,
      });
  }, [page, openedAt]);

  const go = (next: Page) => {
    setPage(next);
    setOpenedAt(Date.now());
  };

  return (
    <div className="app">
      <header>
        <strong>{t('app.title')}</strong>
        <nav>
          {(['bookings', 'tracking', 'claims', 'settings'] as const).map((p) => (
            <button key={p} type="button" aria-current={page === p} onClick={() => go(p)}>
              {t(`nav.${p}`)}
            </button>
          ))}
        </nav>
      </header>
      {page === 'bookings' && <Bookings />}
      {page === 'tracking' && <Tracking />}
      {page === 'claims' && <Claims shipmentId={params.get('shipment') ?? ''} />}
      {page === 'settings' && account && <Settings account={account} />}
      {page === 'settings' && params.get('driver') && <DriverTraining driverId={params.get('driver') ?? ''} />}
    </div>
  );
}
