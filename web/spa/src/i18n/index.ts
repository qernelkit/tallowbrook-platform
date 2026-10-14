import en from './en.json';

type MessageKey = keyof typeof en;

const messages: Record<string, string> = en;

export function t(key: MessageKey, params: Record<string, string | number> = {}): string {
  const template = messages[key] ?? key;
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(params[name] ?? `{${name}}`));
}

export function formatMoney(amountMinor: number, currency: string): string {
  return new Intl.NumberFormat('en-GB', { style: 'currency', currency }).format(amountMinor / 100);
}

export function formatDate(iso: string): string {
  return new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium' }).format(new Date(iso));
}
