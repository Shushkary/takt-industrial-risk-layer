import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import crypto from 'node:crypto'

const root = resolve(import.meta.dirname, '..')
const lockPath = resolve(root, 'package-lock.json')
const outPath = resolve(root, 'dist', 'frontend-sbom.cyclonedx.json')
const lock = JSON.parse(readFileSync(lockPath, 'utf8'))
const rootPackage = lock.packages?.[''] ?? {}
const packages = lock.packages && typeof lock.packages === 'object' ? lock.packages : {}

function purl(name, version) {
  return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`
}

const components = Object.entries(packages)
  .filter(([path, value]) => path.startsWith('node_modules/') && value && typeof value === 'object')
  .map(([path, value]) => {
    const rawName = path.replace(/^node_modules\//, '')
    const version = typeof value.version === 'string' ? value.version : '0.0.0'
    const component = {
      type: 'library',
      'bom-ref': purl(rawName, version),
      name: rawName,
      version,
      purl: purl(rawName, version),
      scope: value.dev ? 'optional' : 'required',
    }
    if (typeof value.license === 'string') {
      component.licenses = [{ license: { id: value.license } }]
    }
    if (typeof value.resolved === 'string' && !value.resolved.startsWith('file:')) {
      component.externalReferences = [{ type: 'distribution', url: value.resolved }]
    }
    return component
  })
  .sort((left, right) => left.name.localeCompare(right.name) || left.version.localeCompare(right.version))

const metadataDependencies = {
  ...(rootPackage.dependencies ?? {}),
  ...(rootPackage.devDependencies ?? {}),
}

const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: [
      {
        vendor: 'TAKT',
        name: 'frontend package-lock SBOM generator',
        version: '1',
      },
    ],
    component: {
      type: 'application',
      'bom-ref': `pkg:npm/${rootPackage.name ?? 'takt-arm'}@${rootPackage.version ?? '0.0.0'}`,
      name: rootPackage.name ?? 'takt-arm',
      version: rootPackage.version ?? '0.0.0',
    },
  },
  components,
  dependencies: [
    {
      ref: `pkg:npm/${rootPackage.name ?? 'takt-arm'}@${rootPackage.version ?? '0.0.0'}`,
      dependsOn: Object.entries(metadataDependencies)
        .map(([name]) => {
          const pkg = packages[`node_modules/${name}`]
          return pkg && typeof pkg.version === 'string' ? purl(name, pkg.version) : null
        })
        .filter(Boolean),
    },
  ],
}

mkdirSync(resolve(root, 'dist'), { recursive: true })
writeFileSync(outPath, `${JSON.stringify(sbom, null, 2)}\n`, 'utf8')
console.log(`frontend_sbom=${outPath}`)
