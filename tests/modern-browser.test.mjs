// Real static output + Chromium tests. Fixtures never enter publish_articles/.
// Install browser once: npx playwright install chromium
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { chromium } from '@playwright/test'
import { validatePublicData } from '../site/frontend/.vitepress/shared.mjs'
import { mkdtemp, cp, mkdir, readFile, writeFile, rm, stat } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { createServer } from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const payload = '# Fixture heading\n\nSyntheticNeedle784 cobalt network 知识验证\n\n' +
  '{{ globalThis.__articleAttack = 49 }}\n{{ 7 * 7 }}\n' +
  '<script setup>globalThis.__articleAttack = 1; import x from "./PRIVATE_SENTINEL.vue"</script>\n' +
  '<img src="https://invalid.example/attack" onerror="globalThis.__articleAttack=2">\n' +
  '<iframe srcdoc="<script>alert(1)</script>"></iframe>\n' +
  '<!-- @include: ../../PRIVATE_SENTINEL.md -->\n\n---\nlayout: home\n---\n' +
  '[run](javascript:alert(1))\n\n| Product | Capability | Context |\n| --- | --- | --- |\n' +
  '| Windows Firewall | Host filtering | `<safe>` |\n' +
  '| Azure Firewall | Workload inspection | <img src=x onerror=alert(4)> |\n\n' +
  '```vue\n<script>globalThis.__articleAttack=3</script>\n```\n'
const hostileTitle = 'Synthetic </script><img src=x onerror=alert(1)> {{ 7 * 7 }}'
let fixture, server, origin, browser
const errors = []
const requests = []

function build(repo, output) {
  execFileSync('python3', ['-B', path.join(root, 'scripts/modern_site.py'), 'build', '--repo', repo, '--output', output],
    { cwd: root, stdio: 'pipe', timeout: 120000 })
}

before(async () => {
  fixture = await mkdtemp(path.join(root, '_build-temp-browser-'))
  await cp(path.join(root, 'scripts'), path.join(fixture, 'scripts'), { recursive: true })
  await cp(path.join(root, 'site/frontend'), path.join(fixture, 'site/frontend'), { recursive: true })
  await mkdir(path.join(fixture, 'publish_articles'))
  build(fixture, 'empty-site')
  for (const [slug, title, body] of [
    ['synthetic-security', hostileTitle, payload],
    ['synthetic-other', 'Synthetic other note', 'Another fixture about astronomy.\n']
  ]) {
    await writeFile(path.join(fixture, 'publish_articles', `${slug}.md`), body)
    await writeFile(path.join(fixture, 'publish_articles', `${slug}.json`), JSON.stringify({
      title, sha256: createHash('sha256').update(body).digest('hex')
    }))
  }
  await writeFile(path.join(fixture, 'PRIVATE_SENTINEL.md'), 'Never import this checkout file')
  await mkdir(path.join(fixture, 'public'))
  await writeFile(path.join(fixture, 'public/leak.json'), '{"private":"no"}')
  build(fixture, '_site')
  // Exercise verified replacement, not arbitrary recursive removal of _site.
  build(fixture, '_site')
  server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://localhost')
      const isEmpty = url.pathname.startsWith('/empty/')
      const base = path.join(fixture, isEmpty ? 'empty-site' : '_site')
      const route = isEmpty ? url.pathname.slice('/empty'.length) : url.pathname
      let filename = path.resolve(base, '.' + decodeURIComponent(route))
      if (filename !== base && !filename.startsWith(base + path.sep)) throw new Error('Traversal')
      if ((await stat(filename)).isDirectory()) filename = path.join(filename, 'index.html')
      const ext = path.extname(filename)
      response.setHeader('Content-Type', ({ '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.woff2': 'font/woff2' })[ext] || 'application/octet-stream')
      response.end(await readFile(filename))
    } catch { response.writeHead(404); response.end('Not found') }
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  origin = `http://127.0.0.1:${server.address().port}`
  browser = await chromium.launch({ headless: true })
}, { timeout: 180000 })

after(async () => {
  await browser?.close()
  if (server) await new Promise(resolve => server.close(resolve))
  if (fixture) await rm(fixture, { recursive: true, force: true })
})

async function pageAt(route, viewport = { width: 1440, height: 1000 }) {
  const page = await browser.newPage({ viewport })
  page.on('pageerror', error => errors.push(error.message))
  page.on('request', request => { if (!request.url().startsWith(origin)) requests.push(request.url()) })
  await page.goto(origin + route, { waitUntil: 'networkidle' })
  return page
}

test('SSR article renders literal malicious text without executable article HTML', async () => {
  const html = await readFile(path.join(fixture, '_site/wiki/synthetic-security/index.html'), 'utf8')
  assert.match(html, /SyntheticNeedle784/)
  assert.match(html, /&lt;script setup&gt;/)
  const page = await pageAt('/wiki/synthetic-security/')
  // VitePress inserts a zero-width character inside its permalink anchor;
  // compare the title text node, not that separate navigation control.
  const renderedTitle = await page.locator('#article-title').evaluate(el => el.firstChild.textContent)
  assert.equal(renderedTitle, hostileTitle)
  assert.match(await page.locator('.article-body').innerText(), /\{\{ 7 \* 7 \}\}/)
  assert.equal(await page.locator('.article-body script, .article-body img, .article-body iframe').count(), 0)
  assert.equal(await page.evaluate(() => globalThis.__articleAttack), undefined)
  assert.equal(await page.locator('.VPSidebar img').count(), 0)
  await page.close()
})

test('real VitePress local search finds body-only English and Chinese fixture queries', async () => {
  const page = await pageAt('/')
  await page.locator('.VPNavBarSearch button').click()
  const input = page.locator('#localsearch-input')
  await input.fill('SyntheticNeedle784')
  await page.waitForSelector('.VPLocalSearchBox .result')
  assert.match(await page.locator('.VPLocalSearchBox').innerText(), /Synthetic/)
  assert.equal(await page.locator('.VPLocalSearchBox img').count(), 0)
  await input.fill('NoSuchSyntheticNeedle000')
  await page.waitForFunction(() => !document.querySelector('.VPLocalSearchBox .result'))
  await input.fill('知识验证')
  await page.waitForFunction(() => document.querySelector('.VPLocalSearchBox .result'))
  assert.match(await page.locator('.VPLocalSearchBox').innerText(), /Synthetic/)
  await input.fill('SyntheticNeedle784')
  await page.locator('.VPLocalSearchBox .result').first().click()
  await page.waitForURL(/wiki\/synthetic-security/)
  assert.equal(await page.evaluate(() => globalThis.__articleAttack), undefined)
  await page.close()
})

test('wiki sidebar and client-side body filter use public data as text', async () => {
  const page = await pageAt('/wiki/')
  assert.ok(await page.locator('.VPSidebar').isVisible())
  await page.locator('#wiki-query').fill('cobalt')
  assert.equal(await page.locator('.note-card').count(), 1)
  await page.locator('#wiki-query').fill('does-not-exist')
  assert.match(await page.locator('main').innerText(), /No matching notes/)
  assert.equal(await page.locator('main img').count(), 0)
  await page.close()
})

test('dark mode toggles and persists after navigation', async () => {
  const page = await pageAt('/')
  const wasDark = await page.locator('html').evaluate(el => el.classList.contains('dark'))
  await page.locator('.VPNavBarAppearance button').click()
  assert.equal(await page.locator('html').evaluate(el => el.classList.contains('dark')), !wasDark)
  await page.goto(origin + '/wiki/', { waitUntil: 'networkidle' })
  assert.equal(await page.locator('html').evaluate(el => el.classList.contains('dark')), !wasDark)
  await page.close()
})

test('mobile home and wiki have no horizontal overflow and usable navigation', async () => {
  const page = await pageAt('/', { width: 390, height: 844 })
  for (const route of ['/', '/wiki/', '/wiki/synthetic-security/']) {
    await page.goto(origin + route, { waitUntil: 'networkidle' })
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), route)
  }
  const table = page.locator('.markdown-table-scroll')
  assert.equal(await table.locator('table').count(), 1)
  assert.equal(await table.locator('th').count(), 3)
  assert.equal(await table.locator('td').count(), 6)
  assert.ok(await table.evaluate(el => el.scrollWidth > el.clientWidth))
  assert.equal(await table.locator('img, script, iframe').count(), 0)
  await page.locator('.VPNavBarHamburger').click()
  assert.ok(await page.locator('.VPNavScreen').isVisible())
  await page.close()
})

test('only modern routes are published and navigation has no historical claims', async () => {
  const deleted = (await readFile(path.join(root, 'docs/legacy-deleted-files.txt'), 'utf8')).trim().split('\n')
  // The old root index is intentionally replaced by the modern homepage.
  const retired = deleted.filter(name => name !== 'index.html').map(name => '/' + name)
  for (const route of ['/archive/', '/archives/', '/legacy/', '/2016/post/', '/downloads/tool.exe', ...retired]) {
    assert.equal((await fetch(origin + route)).status, 404, route)
  }
  for (const route of ['/', '/wiki/', '/wiki/synthetic-security/']) {
    const page = await pageAt(route)
    const links = await page.locator('a').evaluateAll(nodes => nodes.map(node => node.getAttribute('href')))
    assert.ok(links.every(href => !/^(?:\/(?:archive|legacy|2016|downloads)(?:\/|$))|\/blob\//.test(href)), route)
    assert.doesNotMatch(await page.locator('body').innerText(), /archive|legacy|download|历史归档|旧站/i)
    await page.close()
  }
})

test('frontend data contract rejects legacy and download pollution', () => {
  assert.deepEqual(validatePublicData({ articles: [] }), { articles: [] })
  for (const extra of [{ legacy: [] }, { downloads: [] }, { legacy: [], downloads: [] }]) {
    assert.throws(() => validatePublicData({ articles: [], ...extra }), /Expected only staged public articles/)
  }
  assert.throws(() => validatePublicData({ articles: [{ slug: 'note', title: 'Note', body: '', html: '', private: 'secret' }] }), /Invalid staged public article/)
})

test('empty fixture artifact has honest empty state and no approval/checkout files', async () => {
  const empty = await readFile(path.join(fixture, 'empty-site/wiki/index.html'), 'utf8')
  assert.match(empty, /No public wiki notes yet/)
  assert.doesNotMatch(empty, /SyntheticNeedle784|archive|legacy|downloads|历史归档|旧站/i)
  const home = await readFile(path.join(fixture, 'empty-site/index.html'), 'utf8')
  assert.match(home, /No wiki notes have been published yet/)
  assert.doesNotMatch(home, /archive|legacy|downloads|历史归档|旧站/i)
  const receipt = JSON.parse(await readFile(path.join(fixture, 'empty-site.build-receipt.json'), 'utf8'))
  for (const name of Object.keys(receipt)) {
    assert.ok(!/(?:^|\/)(?:scripts|tests|publish_articles|site|node_modules|\.git|archive|legacy|2016|downloads)\//.test(name), name)
    assert.ok(!/\.(?:exe|cpp|md|py|vue|map)$/.test(name), name)
    assert.ok(!name.endsWith('.json') || name === 'hashmap.json', name)
  }
  assert.equal((await fetch(origin + '/leak.json')).status, 404)
})

test('standalone presentation retains reviewed bytes, embedded images and stepped navigation', async () => {
  const original = await readFile(path.join(root, 'site/frontend/talks/ai-work-practice/index.html'))
  assert.deepEqual(await readFile(path.join(fixture, '_site/talks/ai-work-practice/index.html')), original)
  const home = await pageAt('/')
  const entry = home.locator('a[href="/talks/ai-work-practice/"]')
  assert.equal(await entry.getAttribute('target'), '_blank')
  const [opened] = await Promise.all([home.waitForEvent('popup'), entry.click()])
  await opened.waitForLoadState('networkidle')
  assert.match(opened.url(), /\/talks\/ai-work-practice\//)
  await opened.close()
  await home.close()
  const page = await pageAt('/talks/ai-work-practice/')
  assert.equal(await page.locator('.slide').count(), 10)
  assert.equal(await page.locator('.slide.active').count(), 1)
  assert.equal(await page.locator('#prev').isDisabled(), true)
  assert.ok(await page.locator('#stage img').evaluateAll(images =>
    images.length === 7 && images.every(img => img.complete && img.naturalWidth > 0 && img.src.startsWith('data:image/'))))
  await page.keyboard.press('ArrowRight')
  await page.keyboard.press('ArrowRight')
  assert.equal(await page.locator('.slide.active').getAttribute('data-step'), '0')
  await page.locator('#next').click()
  assert.equal(await page.locator('.slide.active').getAttribute('data-step'), '1')
  await page.keyboard.press('Space')
  assert.equal(await page.locator('.slide.active').getAttribute('data-step'), '2')
  await page.keyboard.press('ArrowLeft')
  assert.equal(await page.locator('.slide.active').getAttribute('data-step'), '1')
  await page.keyboard.press('o')
  assert.equal(await page.locator('#overview-grid button').count(), 10)
  await page.locator('#overview-grid button').nth(3).click()
  await page.locator('[data-image="limit"]').click()
  assert.ok(await page.locator('#image-dialog').isVisible())
  assert.ok(await page.locator('#full-image').evaluate(img => img.complete && img.naturalWidth > 0))
  await page.keyboard.press('Escape')
  await page.keyboard.press('n')
  assert.match(await page.locator('#notes-content').innerText(), /30 AI Credits/)
  await page.keyboard.press('Escape')
  await page.keyboard.press('h')
  assert.ok(await page.locator('#help-dialog').isVisible())
  await page.keyboard.press('Escape')
  await page.keyboard.press('End')
  assert.equal(await page.locator('#next').isDisabled(), true)
  await page.keyboard.press('Home')
  assert.equal(await page.locator('#prev').isDisabled(), true)
  await page.goto(origin + '/talks/ai-work-practice/#slide=7&step=1', { waitUntil: 'networkidle' })
  // Fragment-only navigation does not reload the standalone document.
  await page.reload({ waitUntil: 'networkidle' })
  assert.equal(await page.locator('.canvas-reveal').evaluate(el => el.inert), false)
  await page.locator('#fullscreen').click()
  await page.waitForFunction(() => !!document.fullscreenElement)
  await page.locator('#fullscreen').click()
  await page.waitForFunction(() => !document.fullscreenElement)
  await page.emulateMedia({ media: 'print' })
  assert.ok(await page.locator('.slide').evaluateAll(slides => slides.every(s => getComputedStyle(s).display === 'block')))
  await page.close()
})

test('reading hook connects to existing cases without adding slides or clipping text', async () => {
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }, { width: 844, height: 390 }]) {
    const page = await pageAt('/talks/ai-work-practice/#slide=7&step=0', viewport)
    await page.emulateMedia({ reducedMotion: 'reduce' })
    assert.equal(await page.locator('.slide').count(), 10)
    assert.ok(await page.locator('.book-hook').isVisible())
    assert.match(await page.locator('.book-hook h2').innerText(), /熟悉的方法，\n会不会限制了我们？/)
    assert.match(await page.locator('.book-card').innerText(), /成长的边界/)
    assert.match(await page.locator('.book-card').getAttribute('aria-label'), /非实体书封面/)
    assert.equal(await page.locator('.canvas-reveal').evaluate(el => el.inert), true)
    await page.keyboard.press('n')
    const notes = await page.locator('#notes-content').innerText()
    assert.match(notes, /讲者提供的概括，未核对为书中逐字原文或页码/)
    assert.match(notes, /第 12 章“刻意的初学者”/)
    assert.match(notes, /本页 3 分钟/)
    await page.keyboard.press('Escape')
    await page.locator('#next').click()
    assert.equal(await page.locator('.book-hook').isVisible(), false)
    assert.equal(await page.locator('.canvas-reveal').evaluate(el => el.inert), false)
    assert.match(await page.locator('.case-insight').innerText(), /CLI 只能输出文字/)
    await page.locator('#prev').click()
    assert.ok(await page.locator('.book-hook').isVisible())
    // All meaningful text remains inside the fixed 1280x720 slide at both reveal states.
    for (let step = 0; step <= 1; step++) {
      assert.deepEqual(await page.locator('.slide.active').evaluate(slide => {
        const frame = slide.getBoundingClientRect()
        return [...slide.querySelectorAll('p,h2')].filter(el => {
          const r = el.getBoundingClientRect()
          return el.checkVisibility({ checkOpacity: true }) && (r.left < frame.left - 1 || r.right > frame.right + 1 || r.top < frame.top - 1 || r.bottom > frame.bottom + 1 || el.scrollWidth > el.clientWidth + 1)
        }).map(el => el.textContent)
      }), [])
      if (step === 0) await page.locator('#next').click()
    }
    await page.locator('#next').click()
    assert.match(await page.locator('.slide.active .context').innerText(), /GUI 点击不通/)
    assert.match(await page.locator('.slide.active .case-result').innerText(), /拖拽临时规避/)
    await page.locator('#next').click()
    assert.match(await page.locator('.slide.active h2').innerText(), /刻意的初学者/)
    assert.match(await page.locator('.slide.active .steps').innerText(), /放下预设，换种方法/)
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1))
    await page.close()
  }
})

test('standalone mobile layout, touch navigation and screenshot dialogs work', async () => {
  const page = await pageAt('/talks/ai-work-practice/', { width: 390, height: 844 })
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1))
  const box = await page.locator('#stage').boundingBox()
  assert.ok(box.x >= 0 && box.x + box.width <= 391)
  await page.locator('#viewport').evaluate(el => {
    const t = new Touch({ identifier: 1, target: el, clientX: 300, clientY: 200 })
    el.dispatchEvent(new TouchEvent('touchstart', { touches: [t] }))
    const end = new Touch({ identifier: 1, target: el, clientX: 100, clientY: 200 })
    el.dispatchEvent(new TouchEvent('touchend', { changedTouches: [end] }))
  })
  assert.match(await page.locator('#position').innerText(), /02 \/ 10/)
  await page.goto(origin + '/talks/ai-work-practice/#slide=7&step=1', { waitUntil: 'networkidle' })
  // Fragment-only navigation does not reload the standalone document.
  await page.reload({ waitUntil: 'networkidle' })
  await page.locator('[data-image="canvas"]').click()
  assert.ok(await page.locator('#image-dialog').isVisible())
  assert.ok(await page.locator('#full-image').evaluate(img => img.naturalWidth > 0))
  await page.locator('#image-dialog .dialog-close').click()
  await page.close()
})

test('modern browser pages have no JS errors, injection, or third-party requests', () => {
  assert.deepEqual(errors, [])
  assert.deepEqual(requests, [])
})
