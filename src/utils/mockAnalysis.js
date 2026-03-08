/**
 * Real threat analysis service.
 * Sends file or URL to the FastAPI + Groq AI backend.
 * Vite proxies /api/* → http://localhost:8000
 */

export async function analyseFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch('/api/scan/file', {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Server error ${res.status}`);
  }

  return res.json();
}

export async function analyseUrl(url) {
  const res = await fetch('/api/scan/url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Server error ${res.status}`);
  }

  return res.json();
}
