import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import assert from 'node:assert/strict'

const root = resolve(import.meta.dirname, '..')
const sbomPath = resolve(root, 'dist', 'frontend-sbom.cyclonedx.json')
const cspPath = resolve(root, 'nginx', 'csp.conf')
const packageJsonPath = resolve(root, 'package.json')

const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'))
assert.equal(packageJson.scripts['test:unit:vitest'], 'vitest run', 'frontend unit tests must run Vitest')
assert.equal(packageJson.scripts['test:e2e:playwright'], 'playwright test', 'frontend e2e tests must run Playwright')
for (const dependency of ['vitest', '@testing-library/react', '@testing-library/jest-dom', 'msw', '@playwright/test']) {
  assert.ok(packageJson.devDependencies?.[dependency], `frontend devDependencies must include ${dependency}`)
}

const testSources = [
  'src/app/taktApi.test.ts',
  'src/app/format.test.ts',
  'src/components/ui/DataTable.test.tsx',
  'src/layout/AppShell.test.tsx',
  'src/pages/CaseDetail.test.tsx',
]
const unitTestCount = testSources
  .map((relativePath) => readFileSync(resolve(root, relativePath), 'utf8'))
  .reduce((count, text) => count + (text.match(/\bit(?:\.each)?\(/g) ?? []).length, 0)
assert.ok(unitTestCount >= 30, `frontend must keep at least 30 Vitest unit cases; found ${unitTestCount}`)

assert.ok(existsSync(sbomPath), 'frontend SBOM must exist at dist/frontend-sbom.cyclonedx.json')
const sbom = JSON.parse(readFileSync(sbomPath, 'utf8'))
assert.equal(sbom.bomFormat, 'CycloneDX', 'frontend SBOM must be CycloneDX')
assert.equal(sbom.specVersion, '1.5', 'frontend SBOM must use CycloneDX 1.5')
assert.ok(Array.isArray(sbom.components), 'frontend SBOM components must be an array')
assert.ok(sbom.components.some((component) => component.name === 'react'), 'frontend SBOM must include react')
assert.ok(sbom.components.some((component) => component.name === 'vite'), 'frontend SBOM must include vite')

assert.ok(existsSync(cspPath), 'frontend CSP config must exist at nginx/csp.conf')
const csp = readFileSync(cspPath, 'utf8')
const required = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  'X-Frame-Options "DENY"',
  'X-Content-Type-Options "nosniff"',
  'Referrer-Policy "no-referrer"',
]

for (const marker of required) {
  assert.ok(csp.includes(marker), `CSP config must include ${marker}`)
}

console.log('frontend_release_artifacts_ok=true')
