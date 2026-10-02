<script setup>
import { withBase } from 'vitepress'
import { legacy, downloads } from '../data.js'
import { downloadUrl, legacyPath } from '../../shared.mjs'
</script>

<template>
  <div class="archive-index">
    <section aria-labelledby="legacy-pages">
      <h2 id="legacy-pages">历史页面 <span lang="en">/ Legacy pages</span><a class="header-anchor" href="#legacy-pages" aria-label="链接到历史页面 · Link to legacy pages">​</a></h2>
      <p>保留原始内容与旧版样式，不属于新知识库的搜索范围。<span lang="en">Preserved in their original design; not included in wiki search.</span></p>
      <ul v-if="legacy.length" class="archive-list">
        <li v-for="item in legacy" :key="item.path">
          <a :href="withBase(legacyPath(item.path))" target="_self" data-legacy-link><span>{{ item.title }}</span><span class="archive-path">{{ legacyPath(item.path) }} ↗</span></a>
        </li>
      </ul>
      <p v-else class="empty-state">暂无历史页面索引。<span lang="en">No indexed legacy pages are available.</span></p>
      <p><a :href="withBase('/legacy/index.html')" target="_self" data-legacy-link>打开旧站首页 · Open the original homepage →</a></p>
    </section>
    <section aria-labelledby="public-downloads">
      <h2 id="public-downloads">公开资源 <span lang="en">/ Downloads</span><a class="header-anchor" href="#public-downloads" aria-label="链接到公开资源 · Link to downloads">​</a></h2>
      <p>链接指向公开仓库中的固定版本，不在本站托管或运行。旧程序可能已不适用于当前系统，请先检查源码与来源。</p>
      <p lang="en">Links point to pinned revisions in the public repository, not files hosted or executed here. Historical programs may be incompatible with current systems; inspect the source and provenance before use.</p>
      <ul v-if="downloads.length" class="archive-list download-list">
        <li v-for="item in downloads" :key="item.url">
          <a :href="downloadUrl(item.url)" target="_blank" rel="noopener noreferrer"><span>{{ item.name }}</span><span class="archive-path">GitHub · 固定版本 / Pinned revision ↗</span></a>
        </li>
      </ul>
      <p v-else class="empty-state">暂无公开下载链接。<span lang="en">No public downloads are listed.</span></p>
    </section>
  </div>
</template>
