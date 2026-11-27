// Lets `node --test` run the frontend's TypeScript sources directly (Node ≥ 23 strips
// the types): resolves the Vite alias `@/x` and extensionless relative imports to `.ts`.
import { registerHooks } from 'node:module'
import { existsSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'

const SRC = fileURLToPath(new URL('../src/', import.meta.url))

registerHooks({
  resolve(specifier, context, next) {
    let target = null
    if (specifier.startsWith('@/')) target = SRC + specifier.slice(2)
    else if (/^\.\.?\//.test(specifier) && context.parentURL?.startsWith('file:') && !/\.[cm]?[jt]sx?$/.test(specifier)) {
      target = fileURLToPath(new URL(specifier, context.parentURL))
    }
    if (target) {
      for (const ext of ['', '.ts', '.tsx', '/index.ts']) {
        if (existsSync(target + ext) && (ext || /\.[cm]?[jt]sx?$/.test(target))) {
          return next(pathToFileURL(target + ext).href, context)
        }
      }
    }
    return next(specifier, context)
  },
})
