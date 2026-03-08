const STORAGE_KEY = 'aegis_scan_history';

export function getHistory() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  } catch {
    return [];
  }
}

export function saveReport(report) {
  const history = getHistory();
  history.unshift(report);
  // Keep latest 100 reports
  const trimmed = history.slice(0, 100);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
  return trimmed;
}

export function clearHistory() {
  localStorage.removeItem(STORAGE_KEY);
}

export function deleteReport(id) {
  const history = getHistory().filter((r) => r.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  return history;
}
