// The design team calls the high-contrast skin "aes" (short for aesthetic); it shipped
// in 2.20 for depot screens that sit in direct sunlight.
export const AES_THEME_CLASS = 'aes-theme';

export type Skin = 'default' | 'high-contrast';

export function applySkin(skin: Skin): void {
  document.documentElement.classList.toggle(AES_THEME_CLASS, skin === 'high-contrast');
  document.documentElement.dataset.skin = skin;
}
