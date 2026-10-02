<script setup>
import { withBase } from 'vitepress'
import { articles, legacy } from '../data.js'
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
      <a class="explore-card" :href="withBase('/archive/')">
        <span class="card-number" aria-hidden="true">02 / ARCHIVE</span>
        <h3>历史归档 <span lang="en">Earlier chapters.</span></h3>
        <p>保留历史页面与公开资源的访问入口。<span lang="en">Find preserved pages and public resource links.</span></p>
        <span class="card-cta">{{ legacy.length }} 个历史入口 · Legacy links <span aria-hidden="true">↗</span></span>
      </a>
      <a class="explore-card" :href="withBase('/legacy/index.html')" target="_self" data-legacy-link>
        <span class="card-number" aria-hidden="true">03 / ORIGINAL</span>
        <h3>旧站原貌 <span lang="en">As it was.</span></h3>
        <p>进入保留的旧版主页，继续访问熟悉的页面。<span lang="en">Visit the original homepage in its historical design.</span></p>
        <span class="card-cta">打开旧站 · Open legacy site <span aria-hidden="true">↗</span></span>
      </a>
    </div>
    <div v-if="!articles.length" class="home-empty">
      <span class="status-dot" aria-hidden="true" />
      <p>知识库尚无公开文章；历史归档仍可访问。<span lang="en">No wiki notes have been published yet. The historical archive remains available.</span></p>
      <a :href="withBase('/archive/')">查看归档 · View archive →</a>
    </div>
    <p class="home-colophon">中文为主，中英并置。<span lang="en">Chinese first, with English alongside.</span></p>
  </section>
</template>
