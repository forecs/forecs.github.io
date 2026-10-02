<script setup>
import { withBase } from 'vitepress'
import { articles } from '../data.js'
</script>

<template>
  <section class="home-overview" aria-labelledby="explore-title">
    <div class="section-heading">
      <div><p class="eyebrow">THE COLLECTION / 公开记录</p><h2 id="explore-title">从这里开始 <span lang="en">/ Explore</span></h2></div>
      <span class="collection-count">{{ articles.length }} 篇公开笔记 <span lang="en">/ public notes</span></span>
    </div>
    <div class="explore-grid">
      <a class="explore-card" :href="withBase('/wiki/')">
        <span class="card-number" aria-hidden="true">01 / WIKI</span>
        <h3>知识库 <span lang="en">Knowledge, collected.</span></h3>
        <p>公开笔记的入口，支持本地全文搜索。<span lang="en">Browse public notes and search their full text locally.</span></p>
        <span class="card-cta">浏览笔记 · Browse notes <span aria-hidden="true">↗</span></span>
      </a>
    </div>
    <div v-if="!articles.length" class="home-empty">
      <span class="status-dot" aria-hidden="true" />
      <p>知识库尚无公开文章；这里只展示已审核并公开发布的笔记。<span lang="en">No wiki notes have been published yet. Only reviewed, published notes appear here.</span></p>
    </div>
    <p class="home-colophon">中文为主，中英并置。<span lang="en">Chinese first, with English alongside.</span></p>
  </section>
</template>
