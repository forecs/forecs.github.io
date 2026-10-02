import { defineConfig } from 'vitepress'
import publicData from './public-data.json'
import { articleForPage, articlePath, escapeHtml, validatePublicData } from './shared.mjs'

const { articles } = validatePublicData(publicData)

export default defineConfig({
  lang: 'zh-CN',
  title: 'forecs',
  description: '个人主页与公开知识笔记 · Personal home & public wiki',
  base: '/',
  cleanUrls: false,
  appearance: true,
  lastUpdated: false,
  useWebFonts: false,
  // Never copy an arbitrary repository public/ tree. Only generated assets ship.
  vite: { publicDir: false },
  head: [['meta', { name: 'theme-color', content: '#186b60' }]],
  markdown: { html: true },
  transformPageData(page) {
    if (articleForPage(articles, page.relativePath)) {
      // Deliberately static metadata: hostile titles stay runtime data, not
      // Markdown, frontmatter, or Vue template source.
      page.title = '知识笔记 · Wiki'
      page.description = '公开知识笔记 · Public wiki article'
      page.frontmatter.outline = false
      page.frontmatter.prev = false
      page.frontmatter.next = false
    }
  },
  themeConfig: {
    siteTitle: 'forecs / 笔记',
    nav: [
      { text: '首页 Home', link: '/' },
      { text: '知识库 Wiki', link: '/wiki/', activeMatch: '^/wiki/' }
    ],
    sidebar: {
      '/wiki/': [
        { text: '知识库 · Wiki', items: [{ text: '全部笔记 · All notes', link: '/wiki/' }] },
        {
          text: '公开笔记 · Public notes',
          // VitePress 1.6.4 sidebar text uses v-html. Escape even though Vue
          // interpolation in our own components already treats titles as text.
          items: articles.length
            ? articles.map((article) => ({ text: escapeHtml(article.title), link: articlePath(article.slug) }))
            : [{ text: '暂无公开笔记 · No notes yet', link: '/wiki/' }]
        }
      ]
    },
    outline: { label: '本页目录 · On this page', level: [2, 3] },
    sidebarMenuLabel: '目录 · Menu',
    returnToTopLabel: '返回顶部 · Back to top',
    darkModeSwitchLabel: '外观 · Appearance',
    lightModeSwitchTitle: '切换浅色 · Light mode',
    darkModeSwitchTitle: '切换深色 · Dark mode',
    docFooter: { prev: '上一篇 · Previous', next: '下一篇 · Next' },
    footer: {
      message: '公开笔记，持续积累。 · Public notes, collected over time.',
      copyright: 'forecs · Personal home & wiki'
    },
    socialLinks: [{ icon: 'github', link: 'https://github.com/forecs/forecs.github.io', ariaLabel: 'Public site repository on GitHub' }],
    search: {
      provider: 'local',
      options: {
        disableQueryPersistence: true,
        // The default detailed preview mounts Markdown pages in a separate app
        // without our global components. Keep safe title-only results instead.
        disableDetailedView: true,
        translations: {
          button: { buttonText: '搜索 Search', buttonAriaLabel: '搜索公开笔记 · Search public notes' },
          modal: {
            noResultsText: '没有找到结果 · No results for',
            resetButtonTitle: '清空搜索 · Clear search',
            backButtonTitle: '关闭搜索 · Close search',
            footer: { selectText: '打开 · Open', navigateText: '选择 · Navigate', closeText: '关闭 · Close' }
          }
        },
        miniSearch: {
          options: {
            // The same self-contained function is serialized to the client.
            // Word segmentation makes Chinese and English queries useful.
            tokenize: (text) => Array.from(
              new Intl.Segmenter('zh-CN', { granularity: 'word' }).segment(text),
              (part) => part.segment
            ).filter((word) => /[\p{L}\p{N}]/u.test(word))
          }
        },
        _render(source, env, md) {
          const article = articleForPage(articles, env.relativePath)
          if (article) {
            // This HTML goes only to the search indexer, NEVER md.render or
            // the Vue compiler. The anchor matches the SSR article heading.
            return `<h1 id="article-title">${escapeHtml(article.title.replace(/\s+/g, ' '))}<a href="#article-title" aria-hidden="true">#</a></h1>\n${article.html}`
          }
          const html = md.render(source, env)
          return env.frontmatter?.search === false ? '' : html
        }
      }
    }
  }
})
