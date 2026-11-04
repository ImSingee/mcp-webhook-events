// Run before CSS so a saved appearance never flashes the system theme.
(() => {
  try {
    const value = localStorage.getItem('mwe.theme');
    if (value === 'light' || value === 'dark') {
      document.documentElement.dataset.theme = value;
    }
  } catch {
    /* Storage may be disabled; the system preference still works. */
  }
})();
