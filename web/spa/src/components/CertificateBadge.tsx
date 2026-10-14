// Shows a driver's training course and when the course pass runs out.
import type { TrainingCourse } from '../api/types';
import { t } from '../i18n';

type CertificateBadgeProps = { course: TrainingCourse };

export function CertificateBadge({ course }: CertificateBadgeProps) {
  const today = new Date().toISOString().slice(0, 10);
  const certificateExpired = course.certificate.expiresOn < today;
  const until = course.certificate.expiresOn;
  return (
    <span className={certificateExpired ? 'badge badge--expired' : 'badge'} title={course.provider}>
      {course.title}
      {' · '}
      {certificateExpired ? t('training.expired') : t('training.validUntil', { date: until })}
    </span>
  );
}
