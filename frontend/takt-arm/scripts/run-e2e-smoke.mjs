import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { resolve } from 'node:path'
import assert from 'node:assert/strict'

const root = resolve(import.meta.dirname, '..')
const dist = resolve(root, 'dist')

assert.ok(existsSync(dist), 'dist must exist; run npm run build before npm run test:e2e')

const indexHtml = readFileSync(resolve(dist, 'index.html'), 'utf8')
assert.match(indexHtml, /<div id="root"><\/div>/, 'index.html must expose the React root')
assert.match(indexHtml, /assets\/index-.*\.js/, 'index.html must reference a built JS asset')

function collectFiles(dir) {
  const files = []
  for (const item of readdirSync(dir)) {
    const path = resolve(dir, item)
    if (statSync(path).isDirectory()) {
      files.push(...collectFiles(path))
    } else {
      files.push(path)
    }
  }
  return files
}

const builtText = collectFiles(dist)
  .filter((file) => /\.(js|css|html)$/.test(file))
  .map((file) => readFileSync(file, 'utf8'))
  .join('\n')

const expectedRuntimeMarkers = [
  '/cases',
  '/cases/stats',
  '/manual-permits',
  '/operator-actions/viewed',
  '/operator-actions/additional-review',
  '/invariants',
  '/topology/demo-graph',
  '/compliance/mode',
  '/compliance/data-quality-report',
  '/compliance/forensic-readiness',
]

for (const marker of expectedRuntimeMarkers) {
  assert.ok(builtText.includes(marker), `built app must include ${marker}`)
}

const forbiddenMarkers = [
  ['D:', String.fromCharCode(81, 117, 97, 110, 116, 117, 109)].join('/'),
  ['D:', String.fromCharCode(81, 117, 97, 110, 116, 117, 109)].join('\\'),
  [String.fromCharCode(78, 101, 121, 114, 111, 115), 'Prod'].join('_'),
]

for (const marker of forbiddenMarkers) {
  assert.ok(!builtText.includes(marker), `built app must not include forbidden workspace marker: ${marker}`)
}

console.log('frontend_e2e_smoke_ok=true')
