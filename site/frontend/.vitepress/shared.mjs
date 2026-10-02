// Only routing and text escaping live here. This module never parses Markdown.
export const SAFE_SLUG = /^[a-z0-9-]{1,80}$/

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[character])
}

export function articlePath(slug) {
  if (!SAFE_SLUG.test(slug)) throw new Error('Invalid public article slug')
  return `/wiki/${slug}/`
}

export function articleForPage(articles, relativePath) {
  const match = /^wiki\/([a-z0-9-]{1,80})\/index\.md$/.exec(relativePath || '')
  return match ? articles.find((article) => article.slug === match[1]) : undefined
}

// Legacy paths are local allowlisted files, never javascript: or network URLs.
// Historical root index.html has been relocated by the Python stage.
export function legacyPath(path) {
  if (typeof path !== 'string') throw new Error('Invalid legacy path')
  const relative = path.replace(/^\//, '')
  if (!relative || !relative.split('/').every((part) =>
    /^[A-Za-z0-9_-][A-Za-z0-9_.@-]*$/.test(part) && part !== '..'
  )) throw new Error('Invalid legacy path')
  return relative === 'index.html' ? '/legacy/index.html' : `/${relative}`
}

export function downloadUrl(value) {
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
      !['github.com', 'raw.githubusercontent.com'].includes(url.hostname) ||
      !url.pathname.startsWith('/forecs/forecs.github.io/')) {
    throw new Error('Downloads must reference the public GitHub repository')
  }
  // Immutable revision pinning and the exact asset allowlist belong to staging.
  return url.href
}

export function validatePublicData(data) {
  if (!data || !['articles', 'legacy', 'downloads'].every((key) => Array.isArray(data[key]))) {
    throw new Error('Missing staged public data arrays')
  }
  const seen = new Set()
  for (const article of data.articles) {
    if (!article || !['slug', 'title', 'html', 'body'].every((key) => typeof article[key] === 'string') ||
        !SAFE_SLUG.test(article.slug) || seen.has(article.slug)) {
      throw new Error('Invalid staged public article')
    }
    seen.add(article.slug)
  }
  for (const item of data.legacy) {
    if (!item || typeof item.title !== 'string') throw new Error('Invalid legacy title')
    legacyPath(item.path)
  }
  for (const item of data.downloads) {
    if (!item || typeof item.name !== 'string' || typeof item.url !== 'string') {
      throw new Error('Invalid download entry')
    }
    downloadUrl(item.url)
  }
  return data
}
