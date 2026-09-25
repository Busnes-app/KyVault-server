// Busnes.app defaults; explicit choices are local to this browser.
export const THEME_OPTIONS = [{"id": "system", "label": "System (Busnes)"}, {"id": "busnes-light", "label": "Busnes Light"}, {"id": "busnes-dark", "label": "Busnes Dark"}];
export function storedTheme(): string {
  try { const value = localStorage.getItem('kyvault-theme'); return THEME_OPTIONS.find(t => t.id === value)?.id ?? 'system'; }
  catch { return 'system'; }
}
let current = storedTheme();
const media = window.matchMedia?.('(prefers-color-scheme: dark)');
export function applyTheme(theme: string, persist = false) {
  if (!THEME_OPTIONS.some(t => t.id === theme)) return;
  current = theme;
  const resolved = theme === 'system' ? (media?.matches ? 'busnes-dark' : 'busnes-light') : theme;
  document.documentElement.dataset.theme = resolved;
  document.documentElement.style.colorScheme = ['busnes-light', 'paper'].includes(resolved) ? 'light' : 'dark';
  if (persist) try { localStorage.setItem('kyvault-theme', theme); } catch { /* Storage is optional. */ }
}
applyTheme(current);
media?.addEventListener('change', () => { if (current === 'system') applyTheme(current); });
window.addEventListener('storage', e => { if (e.key === 'kyvault-theme' || e.key === null) applyTheme(storedTheme()); });
