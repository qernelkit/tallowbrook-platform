// Seaports we book ocean freight through, keyed by UN/LOCODE. Used to validate
// booking requests and to show port names on labels and tracking pages.

/** @typedef {{ locode: string, name: string, country: string, timeZone: string }} Port */

/** @type {Port[]} */
export const PORTS = [
  { locode: 'GBFXT', name: 'Felixstowe', country: 'GB', timeZone: 'Europe/London' },
  { locode: 'GBSOU', name: 'Southampton', country: 'GB', timeZone: 'Europe/London' },
  { locode: 'GBLGP', name: 'London Gateway', country: 'GB', timeZone: 'Europe/London' },
  { locode: 'NLRTM', name: 'Rotterdam', country: 'NL', timeZone: 'Europe/Amsterdam' },
  { locode: 'BEANR', name: 'Antwerp', country: 'BE', timeZone: 'Europe/Brussels' },
  { locode: 'DEHAM', name: 'Hamburg', country: 'DE', timeZone: 'Europe/Berlin' },
  { locode: 'ESVLC', name: 'Valencia', country: 'ES', timeZone: 'Europe/Madrid' },
  { locode: 'ITGOA', name: 'Genoa', country: 'IT', timeZone: 'Europe/Rome' },
  { locode: 'CNSHA', name: 'Shanghai', country: 'CN', timeZone: 'Asia/Shanghai' },
  { locode: 'CNNGB', name: 'Ningbo', country: 'CN', timeZone: 'Asia/Shanghai' },
  { locode: 'CNSZX', name: 'Shenzhen', country: 'CN', timeZone: 'Asia/Shanghai' },
  { locode: 'SGSIN', name: 'Singapore', country: 'SG', timeZone: 'Asia/Singapore' },
  { locode: 'KRPUS', name: 'Busan', country: 'KR', timeZone: 'Asia/Seoul' },
  { locode: 'MYPKG', name: 'Port Klang', country: 'MY', timeZone: 'Asia/Kuala_Lumpur' },
  { locode: 'AEJEA', name: 'Jebel Ali', country: 'AE', timeZone: 'Asia/Dubai' },
  { locode: 'INNSA', name: 'Nhava Sheva', country: 'IN', timeZone: 'Asia/Kolkata' },
  { locode: 'USNYC', name: 'New York', country: 'US', timeZone: 'America/New_York' },
  { locode: 'USSAV', name: 'Savannah', country: 'US', timeZone: 'America/New_York' },
  { locode: 'USLAX', name: 'Los Angeles', country: 'US', timeZone: 'America/Los_Angeles' },
  { locode: 'BRSSZ', name: 'Santos', country: 'BR', timeZone: 'America/Sao_Paulo' },
];

const BY_LOCODE = new Map(PORTS.map((port) => [port.locode, port]));

/**
 * @param {string} locode
 * @returns {Port | undefined}
 */
export function portByLocode(locode) {
  return BY_LOCODE.get(locode.trim().toUpperCase());
}

/**
 * @param {string} country ISO 3166 alpha-2
 */
export function portsInCountry(country) {
  return PORTS.filter((port) => port.country === country.toUpperCase());
}

/**
 * @param {string} locode
 */
export function isKnownPort(locode) {
  return /^[A-Z]{2}[A-Z2-9]{3}$/.test(locode) && BY_LOCODE.has(locode);
}
