import { readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative } from 'node:path'

const root = process.cwd()
const skippedDirs = new Set(['.git', 'dist', 'node_modules', 'storybook-static'])
const checkedExtensions = new Set([
  '.css',
  '.html',
  '.js',
  '.json',
  '.md',
  '.mjs',
  '.ts',
  '.tsx',
])

const forbiddenPatterns = [
  { name: 'external workspace marker', pattern: new RegExp('forbidden-external' + '-workspace-marker', 'i') },
  { name: 'external workspace name', pattern: new RegExp('Quan' + 'tum', 'i') },
  { name: 'external workspace name', pattern: new RegExp('Neyros' + '_Prod', 'i') },
  { name: 'local file URL', pattern: /file:\/\/\//i },
  { name: 'Python package cache path', pattern: new RegExp('site' + '-packages', 'i') },
  { name: 'Windows absolute local path', pattern: /(?:^|[^A-Za-z0-9_])[A-Z]:[\\/](?!\\?)/ },
  { name: 'developer home path', pattern: /(?:\/Users\/|\/home\/|\/mnt\/[a-z]\/)/i },
]

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (skippedDirs.has(entry)) {
      continue
    }
    const path = join(dir, entry)
    const stat = statSync(path)
    if (stat.isDirectory()) {
      yield* walk(path)
    } else if (stat.isFile() && checkedExtensions.has(extname(path))) {
      yield path
    }
  }
}

const guardScript = 'scripts/check-workspace-boundary.mjs'
const offenders = []
for (const path of walk(root)) {
  const rel = relative(root, path).replaceAll('\\', '/')
  if (rel === guardScript) {
    continue
  }
  const text = readFileSync(path, 'utf8')
  for (const { name, pattern } of forbiddenPatterns) {
    if (pattern.test(text)) {
      offenders.push(`${rel}: ${name}`)
    }
  }
}

const apiClient = readFileSync(join(root, 'src', 'app', 'taktApi.ts'), 'utf8')
const envRequired = ['VITE_TAKT_API_BASE_URL', 'VITE_TAKT_API_KEY']
for (const key of envRequired) {
  if (!apiClient.includes(`import.meta.env.${key}`)) {
    offenders.push(`src/app/taktApi.ts: missing ${key} runtime configuration`)
  }
}

if (offenders.length > 0) {
  console.error('Workspace boundary check failed:')
  for (const offender of offenders) {
    console.error(`- ${offender}`)
  }
  process.exit(1)
}

console.log('workspace_boundary_ok=true')
