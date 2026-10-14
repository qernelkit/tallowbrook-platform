import { useEffect, useState } from 'react';
import { getJson } from '../api/client';
import type { Account, ApproverKeyOptions, TrainingCredential } from '../api/types';
import { EnrolApproverKey } from '../approvers/EnrolApproverKey';
import { CertificateBadge } from '../components/CertificateBadge';
import { verifyTrainingCredential } from '../credentials/vcVerifier';
import { applySkin } from '../styles/aesTheme';
import { t } from '../i18n';

export function Settings({ account }: { account: Account }) {
  const [approverOptions, setApproverOptions] = useState<ApproverKeyOptions | null>(null);
  const [highContrast, setHighContrast] = useState(document.documentElement.dataset.skin === 'high-contrast');

  useEffect(() => {
    if (account.role !== 'approver') return;
    getJson<ApproverKeyOptions>(`/v1/accounts/${account.id}/approver-keys/options`).then(setApproverOptions, () =>
      setApproverOptions(null),
    );
  }, [account]);

  useEffect(() => {
    applySkin(highContrast ? 'high-contrast' : 'default');
  }, [highContrast]);

  return (
    <main>
      <h1>{t('nav.settings')}</h1>
      <section>
        <h2>{t('settings.profile')}</h2>
        <p>
          {account.name} · {account.email}
        </p>
        <label>
          <input type="checkbox" checked={highContrast} onChange={(e) => setHighContrast(e.target.checked)} />
          {t('settings.highContrast')}
        </label>
      </section>
      {approverOptions && (
        <section>
          <h2>{t('approvers.title')}</h2>
          <p>{t('approvers.help')}</p>
          <EnrolApproverKey account={account} options={approverOptions} onEnrolled={() => setApproverOptions(null)} />
        </section>
      )}
    </main>
  );
}

export function DriverTraining({ driverId }: { driverId: string }) {
  const [credential, setCredential] = useState<TrainingCredential | null>(null);
  const [verdict, setVerdict] = useState<string | null>(null);

  useEffect(() => {
    getJson<TrainingCredential>(`/v1/drivers/${driverId}/training`).then(setCredential, () => setCredential(null));
  }, [driverId]);

  async function check() {
    if (!credential) return;
    const result = await verifyTrainingCredential(credential);
    setVerdict(result === 'valid' ? t('drivers.credentialValid') : t('drivers.credentialInvalid'));
  }

  if (!credential) return null;
  return (
    <section>
      <h2>{t('drivers.training')}</h2>
      <CertificateBadge course={credential.credentialSubject.course} />
      <button type="button" onClick={() => void check()}>
        {t('drivers.checkCredential')}
      </button>
      {verdict && <p role="status">{verdict}</p>}
    </section>
  );
}
