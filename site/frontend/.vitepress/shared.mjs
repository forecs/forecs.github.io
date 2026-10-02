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

export function validatePublicData(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data) ||
      Object.keys(data).length !== 1 || !Object.hasOwn(data, 'articles') ||
      !Array.isArray(data.articles)) {
    throw new Error('Expected only staged public articles')
  }
  const seen = new Set()
  for (const article of data.articles) {
    if (!article || Object.keys(article).length !== 4 || !['slug', 'title', 'html', 'body'].every((key) => typeof article[key] === 'string') ||
        !SAFE_SLUG.test(article.slug) || seen.has(article.slug)) {
      throw new Error('Invalid staged public article')
    }
    seen.add(article.slug)
  }
  return data
}
