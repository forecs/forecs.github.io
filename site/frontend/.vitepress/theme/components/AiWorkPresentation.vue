<script setup>
import { computed, ref, onMounted, onBeforeUnmount } from 'vue'
import { slides } from './ai-work-slides.js'
import './ai-work-presentation.css'

const current = ref(0)
const notesOpen = ref(false)
const root = ref(null)
const canFullscreen = ref(false)
const isFullscreen = ref(false)
const message = ref('')
const slide = computed(() => slides[current.value])
const minutes = computed(() => `${slide.value.seconds / 60} 分钟`)
let touch = null
let ignoreClickUntil = 0
function syncHash() {
  const match = /^#slide-(\d+)$/.exec(window.location.hash)
  current.value = match ? Math.min(9, Math.max(0, Number(match[1]) - 1)) : 0
}
function go(index) {
  const next = Math.min(slides.length - 1, Math.max(0, index))
  if (next === current.value) return
  current.value = next
  window.history.pushState(null, '', `#slide-${next + 1}`)
  message.value = ''
}
function isControl(target) {
  return target instanceof Element && !!target.closest('button, a, input, textarea, select, [contenteditable], .ai-notes')
}
function onKey(event) {
  if (event.altKey || event.ctrlKey || event.metaKey || isControl(event.target) && !event.target.closest('button')) return
  if (event.key === 'ArrowRight') { event.preventDefault(); go(current.value + 1) }
  else if (event.key === 'ArrowLeft') { event.preventDefault(); go(current.value - 1) }
  else if (event.key.toLowerCase() === 'n') { event.preventDefault(); notesOpen.value = !notesOpen.value }
}
function onBackground(event) {
  if (Date.now() < ignoreClickUntil || isControl(event.target) || window.getSelection()?.toString()) return
  go(current.value + 1)
}
function touchStart(event) {
  touch = event.touches.length === 1 && !isControl(event.target)
    ? { x: event.touches[0].clientX, y: event.touches[0].clientY } : null
}
function touchEnd(event) {
  if (!touch || !event.changedTouches.length) return
  const dx = event.changedTouches[0].clientX - touch.x
  const dy = event.changedTouches[0].clientY - touch.y
  touch = null
  if (Math.abs(dx) > 55 && Math.abs(dx) > Math.abs(dy) * 1.5) {
    ignoreClickUntil = Date.now() + 600
    go(current.value + (dx < 0 ? 1 : -1))
  }
}
function fullscreenChanged() { isFullscreen.value = document.fullscreenElement === root.value }
async function fullscreen() {
  try {
    if (document.fullscreenElement === root.value) await document.exitFullscreen()
    else if (root.value?.requestFullscreen) await root.value.requestFullscreen()
    else message.value = '此浏览器不支持全屏；仍可正常翻页。'
  } catch { message.value = '全屏不可用；仍可正常翻页。' }
}
onMounted(() => {
  syncHash()
  canFullscreen.value = !!document.fullscreenEnabled && !!root.value?.requestFullscreen
  window.addEventListener('keydown', onKey)
  window.addEventListener('popstate', syncHash)
  window.addEventListener('hashchange', syncHash)
  document.addEventListener('fullscreenchange', fullscreenChanged)
})
onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKey)
  window.removeEventListener('popstate', syncHash)
  window.removeEventListener('hashchange', syncHash)
  document.removeEventListener('fullscreenchange', fullscreenChanged)
})
</script>

<template>
  <main ref="root" class="ai-deck" lang="zh-CN" aria-label="从会问 AI，到把工作做成：二十分钟演示">
    <header class="ai-masthead">
      <a href="/" class="ai-wordmark" aria-label="返回 forecs 首页">forecs<span aria-hidden="true"> / </span><span>工作方法</span></a>
      <span class="ai-edition">AI IN PRACTICE <b> / 20 MIN</b></span>
    </header>

    <section class="ai-stage" :class="[`ai-${slide.kind}`, `ai-motif-${slide.motif}`]"
      aria-labelledby="ai-slide-title" @click="onBackground" @touchstart.passive="touchStart"
      @touchend.passive="touchEnd" @touchcancel="touch = null">
      <div :key="current" class="ai-slide">
        <div class="ai-kicker"><span>{{ slide.pair }} / 05</span><span>{{ slide.category }}</span><span class="ai-kind">{{ slide.kind === 'question' ? '问 QUESTION' : '答 ANSWER' }}</span></div>
        <div class="ai-content">
          <div class="ai-copy">
            <h1 id="ai-slide-title"><span v-for="line in slide.title" :key="line">{{ line }}</span></h1>
            <p class="ai-subtitle">{{ slide.subtitle }}</p>
            <ul class="ai-sr" aria-label="本页关键要点"><li v-for="label in slide.labels" :key="label">{{ label }}</li></ul>
          </div>
          <div class="ai-visual" aria-hidden="true">
            <template v-if="slide.kind === 'question'">
              <span class="ai-question-mark">?</span>
              <div class="ai-question-labels"><span v-for="label in slide.labels" :key="label">{{ label }}</span></div>
              <div class="ai-orbit ai-orbit-one"></div><div class="ai-orbit ai-orbit-two"></div>
            </template>
            <template v-else>
              <div class="ai-answer-grid" :class="{ 'ai-three': slide.labels.length === 3 }">
                <div v-for="(label, index) in slide.labels" :key="label" class="ai-node">
                  <span class="ai-node-index">0{{ index + 1 }}</span><span class="ai-node-label">{{ label }}</span>
                  <span class="ai-node-arrow">↗</span>
                </div>
              </div>
              <div class="ai-verification"><span class="ai-dot"></span>验证，贯穿始终<span class="ai-rule"></span></div>
            </template>
          </div>
        </div>
        <div class="ai-slide-bottom"><span>{{ slide.kind === 'question' ? '从一个真实问题开始' : '让工作更可靠地完成' }}</span><span>{{ slide.window }} <b> / {{ minutes }}</b></span></div>
      </div>
    </section>

    <footer class="ai-controls">
      <div class="ai-pagination"><button type="button" aria-label="上一页（左方向键）" :disabled="current === 0" @click="go(current - 1)">←</button><span class="ai-counter" aria-live="polite" aria-atomic="true"><b>{{ String(current + 1).padStart(2, '0') }}</b> / 10<span class="ai-sr">，{{ slide.title.join('') }}</span></span><button type="button" aria-label="下一页（右方向键）" :disabled="current === 9" @click="go(current + 1)">→</button></div>
      <span class="ai-help">← → 翻页 · 点击画面前进 · 滑动翻页</span>
      <div class="ai-tools"><button type="button" aria-controls="ai-speaker-notes" :aria-expanded="notesOpen" aria-keyshortcuts="N" @click="notesOpen = !notesOpen">{{ notesOpen ? '收起讲稿' : '讲稿' }} <kbd>N</kbd></button><button type="button" :disabled="!canFullscreen" :aria-label="canFullscreen ? (isFullscreen ? '退出全屏' : '进入全屏') : '此浏览器不支持全屏'" @click="fullscreen">{{ isFullscreen ? '退出全屏' : '全屏' }} <span aria-hidden="true">⛶</span></button></div>
    </footer>
    <div class="ai-progress" aria-hidden="true"><span :style="{ width: `${(current + 1) * 10}%` }"></span></div>
    <p v-if="message" class="ai-status" role="status">{{ message }}</p>
    <aside v-show="notesOpen" id="ai-speaker-notes" class="ai-notes" aria-label="当前页演讲稿">
      <div class="ai-notes-heading"><h2>演讲者笔记 <span>{{ current + 1 }} / 10</span></h2><button type="button" @click="notesOpen = false" aria-label="关闭讲稿">关闭 ×</button></div>
      <p class="ai-cue"><b>本页 {{ minutes }} · {{ slide.window }}</b>　{{ slide.cue }}</p>
      <ol><li v-for="[time, text] in slide.notes" :key="time"><h3>{{ time }}</h3><p>{{ text }}</p></li></ol>
      <p class="ai-notes-foot">按累计时间点控制节奏，包含互动和停顿；共 20 分钟，无自动计时或自动翻页。讲稿为公开来源的改编，不代表案例已在本环境复现。</p>
      <div v-if="current === 9" class="ai-references"><h3>来源与核查入口</h3><a href="https://github.com/forecs/forecs.github.io/blob/ceb06e95d7006ab7f7f999586aef5c8d0ae7e75d/publish_articles/ai-work-efficiency-speech-draft.md" target="_blank" rel="noopener noreferrer">演讲原稿 · 固定公开版本 ↗</a><p>制作时公开 PR #6 尚未合并；此演示依据其公开版本改编，未修改或代为发布原稿。下列官方入口应按实际产品版本核查。</p><a href="https://docs.github.com/en/copilot" target="_blank" rel="noopener noreferrer">GitHub Copilot 官方文档 ↗</a><a href="https://learn.microsoft.com/en-us/windows-server/" target="_blank" rel="noopener noreferrer">Windows Server 官方文档 ↗</a><p>这些入口不是 Canvas、computer-use 或 WinRE 能力支持的证据；需要匹配具体产品与版本，再做受控测试。</p></div>
    </aside>
  </main>
</template>
