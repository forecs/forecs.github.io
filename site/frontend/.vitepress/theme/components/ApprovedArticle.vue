<script setup>
import { computed } from 'vue'
import { withBase } from 'vitepress'
import { articles } from '../data.js'

const props = defineProps({ slug: { type: String, required: true } })
const article = computed(() => articles.find((item) => item.slug === props.slug))
</script>

<template>
  <article v-if="article" class="approved-article" aria-labelledby="article-title">
    <p class="eyebrow">公开笔记 <span lang="en">/ PUBLIC WIKI</span></p>
    <h1 id="article-title">{{ article.title }}<a class="header-anchor" href="#article-title" aria-label="链接到标题 · Link to title">​</a></h1>
    <!-- The sole article HTML sink. Python has already rendered and escaped
         the inert subset. Never compile this string or pass it to Markdown. -->
    <div class="article-body" v-html="article.html" />
    <nav class="article-return" aria-label="文章导航 · Article navigation">
      <a :href="withBase('/wiki/')">← 返回知识库 <span lang="en">/ All notes</span></a>
    </nav>
  </article>
  <section v-else class="empty-state" aria-labelledby="missing-title">
    <h1 id="missing-title">笔记不可用 <span lang="en">/ Note unavailable</span></h1>
    <p>这篇笔记不在当前公开目录中。<span lang="en">This note is not in the current public collection.</span></p>
    <a :href="withBase('/wiki/')">返回知识库 · Back to wiki</a>
  </section>
</template>
