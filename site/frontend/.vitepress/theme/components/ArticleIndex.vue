<script setup>
import { computed, ref } from 'vue'
import { withBase } from 'vitepress'
import { articles } from '../data.js'
import { articlePath } from '../../shared.mjs'

const query = ref('')
const visible = computed(() => {
  const words = query.value.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean)
  return articles.filter((article) => {
    const haystack = `${article.title}\n${article.body}`.toLocaleLowerCase()
    return words.every((word) => haystack.includes(word))
  })
})
const excerpt = (body) => {
  const text = body.replace(/\s+/g, ' ').trim()
  return text.length > 180 ? `${text.slice(0, 180)}…` : text
}
</script>

<template>
  <section v-if="!articles.length" class="empty-state" aria-labelledby="empty-wiki-title">
    <div class="empty-symbol" aria-hidden="true">＋</div>
    <h2 id="empty-wiki-title">留白，是下一篇笔记的位置。</h2>
    <p>目前还没有已发布的知识库文章。这里仅展示已审核并公开发布的内容。</p>
    <p lang="en">No public wiki notes yet. Only reviewed, published notes appear here.</p>
    <a class="text-link" :href="withBase('/')">返回首页 <span lang="en">/ Back to home →</span></a>
  </section>
  <section v-else aria-label="公开笔记列表 · Public note list">
    <div class="wiki-filter">
      <label for="wiki-query">筛选笔记 <span lang="en">/ Filter notes</span></label>
      <input id="wiki-query" v-model="query" type="search" placeholder="标题或正文 · Title or text" autocomplete="off" />
      <p class="result-count" role="status">{{ visible.length }} / {{ articles.length }} 篇 <span lang="en">notes</span></p>
    </div>
    <ul v-if="visible.length" class="note-list">
      <li v-for="article in visible" :key="article.slug">
        <article class="note-card">
          <span class="eyebrow">WIKI / 公开笔记</span>
          <h2><a :href="withBase(articlePath(article.slug))">{{ article.title }}</a></h2>
          <p>{{ excerpt(article.body) }}</p>
          <a class="text-link" :href="withBase(articlePath(article.slug))" :aria-label="`阅读 · Read: ${article.title}`">阅读笔记 <span lang="en">/ Read note →</span></a>
        </article>
      </li>
    </ul>
    <div v-else class="empty-state">
      <h2>没有匹配的笔记 <span lang="en">/ No matching notes</span></h2>
      <p>试试更短的关键词，或清空筛选。<span lang="en">Try fewer keywords, or clear the filter.</span></p>
      <button class="quiet-button" type="button" @click="query = ''">清空筛选 · Clear filter</button>
    </div>
  </section>
</template>
