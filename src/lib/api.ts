const base = import.meta.env.MODE === "pages" ? import.meta.env.VITE_API_BASE : "";

export function apiFetch(path: string, init?: RequestInit) {
  return fetch(`${base}${path}`, {
    ...init,
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
}

export function assetPath(path: string) {
  return `${import.meta.env.BASE_URL}${path}`;
}
