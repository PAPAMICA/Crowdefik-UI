/**
 * Return a favicon URL for a given hostname using Google's public favicon service.
 * Falls back gracefully if the host has no favicon.
 */
export function faviconUrl(host: string): string {
  const domain = host.split(':')[0] // strip port
  return `https://www.google.com/s2/favicons?sz=32&domain=${encodeURIComponent(domain)}`
}
