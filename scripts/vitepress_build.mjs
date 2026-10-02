// Trusted build driver. Inventory comes from Rollup's client bundle, NOT a glob
// over dist. Python rejects any other output (including copied checkout files).
import { build } from 'vitepress'
import { readFile, writeFile, lstat } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import path from 'node:path'

const [source, dist, receipt] = process.argv.slice(2)
if (!source || !dist || !receipt) throw new Error('source, dist, receipt required')
const inventory = Object.create(null)
const sha = data => createHash('sha256').update(data).digest('hex')
const publicDataPath = path.join(source, '.vitepress/public-data.json')
const publicDataSha256 = sha(await readFile(publicDataPath))
let pages
await build(source, {
  outDir: dist,
  onAfterConfigResolve(config) {
    pages = ['404.html', ...config.pages.map(p => p.replace(/\.md$/, '.html'))]
    // Trusted settings cannot accidentally turn checkout/public into an artifact.
    config.vite = {
      ...config.vite,
      publicDir: false,
      plugins: [...(config.vite?.plugins || []), {
        name: 'exact-public-bundle-inventory',
        enforce: 'post',
        writeBundle(options, bundle) {
          if (path.resolve(options.dir) !== path.resolve(dist)) return
          for (const item of Object.values(bundle)) {
            inventory[item.fileName] = sha(item.type === 'chunk' ? item.code : item.source)
          }
        }
      }],
      build: { ...config.vite?.build, sourcemap: false }
    }
  }
})
for (const name of [...pages, 'hashmap.json', 'vp-icons.css']) {
  const file = path.join(dist, name)
  if (!(await lstat(file)).isFile()) throw new Error(`Not a regular output: ${name}`)
  inventory[name] = sha(await readFile(file))
}
if (publicDataSha256 !== sha(await readFile(publicDataPath))) {
  throw new Error('Staged public data changed during build')
}
await writeFile(receipt, JSON.stringify({ files: inventory, publicDataSha256 }, null, 2) + '\n', { flag: 'wx' })
