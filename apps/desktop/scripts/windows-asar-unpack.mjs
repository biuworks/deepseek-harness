/** Keep prepared Windows PE files outside ASAR without changing their sealed bytes. */
import { cp, lstat, mkdir, mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import { readAsar } from 'app-builder-lib/out/asar/asar.js'
import { windowsRuntimeCode } from './windows-runtime-signature.mjs'

function inside(root, file) {
  const suffix = relative(root, file)
  return suffix !== '..' && !suffix.startsWith(`..${sep}`) && !isAbsolute(suffix)
}

function unpackPattern(path) {
  // Builder removes backslash escapes; brace expansion also ignores character classes.
  // A brace matches one character, so similarly named neighbors may also be unpacked.
  return path.split(sep).join('/').replace(/[\[\]{}()*?+@#]/gu,
    character => character === '{' || character === '}' ? '?' : `[${character}]`).replace(/^!/u, '@(!)')
}

/**
 * List every file of the installed LibreOffice engine packages.
 * The native helper reads uno.ini, services.rdb, and other non-PE data from its
 * program directory on the real filesystem, so the whole engine package must be
 * unpacked beside the PE files, not sealed inside the ASAR archive.
 * @param {string} sourceRoot Verified prepared dsh directory.
 * @returns {Promise<string[]>} Absolute engine package file paths.
 */
async function officeEnginePackageFiles(sourceRoot) {
  const scopeDir = join(sourceRoot, 'node_modules', '@deepseek-ai')
  const files = []
  let entries
  try { entries = await readdir(scopeDir, { withFileTypes: true }) } catch { return files }
  for (const entry of entries) {
    if (!entry.isDirectory() || !/^libreoffice-kit-(?:win32|darwin|linux)-/u.test(entry.name)) continue
    const walk = async directory => {
      for (const child of await readdir(directory, { withFileTypes: true })) {
        const path = join(directory, child.name)
        if (child.isDirectory()) await walk(path)
        else if (child.isFile()) files.push(path)
      }
    }
    await walk(join(scopeDir, entry.name))
  }
  return files
}

/**
 * Install source-relative unpack patterns in the configuration consumed by electron-builder.
 * @param {import('app-builder-lib').BeforePackContext} context Active builder configuration and cleanup owner.
 * @param {string} sourceRoot Verified prepared dsh directory; its files remain unchanged.
 * @returns {Promise<string[]>} Unpacked file paths (PE code and complete Office engines) relative to the original prepared directory.
 */
export async function prepareWindowsAsarUnpack(context, sourceRoot) {
  const files = [...new Set([
    ...(await windowsRuntimeCode(sourceRoot)),
    ...(await officeEnginePackageFiles(sourceRoot)),
  ])].map(file => relative(sourceRoot, file))
  const { config, info } = context.packager
  const { appDir } = info
  let copyRoot = sourceRoot
  if (!inside(appDir, sourceRoot)) {
    // Builder's source matcher slices the appDir prefix even for external FileSets.
    const parent = join(appDir, '.desktop-build')
    await mkdir(parent, { recursive: true })
    const stage = await mkdtemp(join(parent, 'asar-source-'))
    copyRoot = join(stage, 'dsh')
    info.disposeOnBuildFinish(() => rm(stage, { recursive: true, force: true }))
    await cp(sourceRoot, copyRoot, { recursive: true, force: false, errorOnExist: true })
    config.files = config.files.map(file => {
      if (typeof file === 'string' || file.from === undefined) return file
      const from = resolve(appDir, file.from)
      return inside(sourceRoot, from) ? { ...file, from: join(copyRoot, relative(sourceRoot, from)) } : file
    })
  }
  const existing = config.asarUnpack ?? []
  config.asarUnpack = [...(typeof existing === 'string' ? [existing] : existing),
    ...files.map(file => unpackPattern(relative(appDir, join(copyRoot, file))))]
  return files
}

/**
 * Reject inline, absent, linked, or changed PE files in the assembled application.
 * @param {string} sourceRoot Original signed and sealed dsh directory.
 * @param {string} resourcesDir Assembled application resources directory.
 * @param {string[]} files PE paths returned by prepareWindowsAsarUnpack.
 * @returns {Promise<void>} Resolves after every PE has an unpacked ASAR entry and identical bytes.
 */
export async function verifyWindowsAsarUnpack(sourceRoot, resourcesDir, files) {
  const archive = await readAsar(join(resourcesDir, 'app.asar'))
  for (const file of files) {
    const entry = archive.getFile(join('dsh', file), false)
    if (entry.unpacked !== true || entry.link !== undefined) {
      throw new Error(`Windows ASAR: PE must be unpacked: ${file}`)
    }
    const copied = join(resourcesDir, 'app.asar.unpacked', 'dsh', file)
    const stat = await lstat(copied)
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Windows ASAR: expected a real PE file: ${file}`)
    const [prepared, packaged] = await Promise.all([readFile(join(sourceRoot, file)), readFile(copied)])
    if (!prepared.equals(packaged)) throw new Error(`Windows ASAR: PE bytes changed: ${file}`)
  }
}
