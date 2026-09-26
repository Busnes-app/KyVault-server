// Firefox exposes promise-returning APIs on both namespaces; Chrome only on chrome.
export const ext: typeof chrome = (globalThis as { browser?: typeof chrome }).browser ?? chrome;
