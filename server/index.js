import { timingSafeEqual } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { access, stat } from 'node:fs/promises'
import { createServer } from 'node:http'
import { extname, join, posix, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createReviewsStore } from './reviewsStore.js'

const ROOT_DIR = resolve(fileURLToPath(new URL('..', import.meta.url)))
const DIST_DIR = resolve(ROOT_DIR, 'dist')

function readPositiveIntEnv(name, fallback) {
  const raw = process.env[name]
  if (!raw) return fallback

  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed <= 0 || !Number.isInteger(parsed)) {
    return fallback
  }

  return parsed
}

function readBooleanEnv(name, fallback) {
  const raw = (process.env[name] || '').trim().toLowerCase()
  if (!raw) return fallback

  if (raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on') return true
  if (raw === '0' || raw === 'false' || raw === 'no' || raw === 'off') return false
  return fallback
}

const MAX_BODY_SIZE = readPositiveIntEnv('MAX_BODY_SIZE', 100_000)
const REQUEST_TIMEOUT_MS = readPositiveIntEnv('REQUEST_TIMEOUT_MS', 10_000)
const RATE_LIMIT_WINDOW_MS = readPositiveIntEnv('RATE_LIMIT_WINDOW_MS', 10 * 60_000)
const RATE_LIMIT_MAX_POSTS = readPositiveIntEnv('RATE_LIMIT_MAX_POSTS', 20)
const PORT = readPositiveIntEnv('PORT', 3001)
const ADMIN_API_TOKEN = (process.env.ADMIN_API_TOKEN || '').trim()
const CONTACT_TO_EMAIL = (process.env.CONTACT_TO_EMAIL || 'mathis.lallemmand2@gmail.com').trim()
const CONTACT_FROM_EMAIL = (process.env.CONTACT_FROM_EMAIL || process.env.SMTP_USER || '').trim()
const SMTP_HOST = (process.env.SMTP_HOST || '').trim()
const SMTP_PORT = readPositiveIntEnv('SMTP_PORT', 465)
const SMTP_SECURE = readBooleanEnv('SMTP_SECURE', SMTP_PORT === 465)
const SMTP_USER = (process.env.SMTP_USER || '').trim()
const SMTP_PASS = (process.env.SMTP_PASS || '').trim()

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8' }
const MIME_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
}

const corsOriginEnv = process.env.CORS_ORIGIN || ''
const allowAnyCorsOrigin = corsOriginEnv.trim() === '*'
const allowedCorsOrigins = new Set(
  corsOriginEnv
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value && value !== '*'),
)
const trustedOriginHosts = new Set(['mathislallemand.fr', 'www.mathislallemand.fr'])

const postRateLimitStore = new Map()
let contactTransporter = null
let nodemailerModulePromise = null
const rateLimitSweepTimer = setInterval(() => {
  const now = Date.now()
  for (const [ip, entry] of postRateLimitStore.entries()) {
    if (entry.resetAt <= now) {
      postRateLimitStore.delete(ip)
    }
  }
}, Math.max(30_000, Math.floor(RATE_LIMIT_WINDOW_MS / 2)))
rateLimitSweepTimer.unref?.()

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()')
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin')
  res.setHeader('X-DNS-Prefetch-Control', 'off')
}

function appendVaryHeader(res, value) {
  const current = res.getHeader('Vary')
  if (!current) {
    res.setHeader('Vary', value)
    return
  }

  const parts = String(current)
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
  if (!parts.includes(value)) {
    parts.push(value)
    res.setHeader('Vary', parts.join(', '))
  }
}

function getRequestOrigin(req) {
  return typeof req.headers.origin === 'string' ? req.headers.origin.trim() : ''
}

function getRequestHost(req) {
  if (typeof req.headers['x-forwarded-host'] === 'string') {
    const forwardedHost = req.headers['x-forwarded-host'].split(',')[0]?.trim()
    if (forwardedHost) return forwardedHost
  }

  return typeof req.headers.host === 'string' ? req.headers.host.trim() : ''
}

function isSameOriginRequest(req, origin) {
  if (!origin) return true

  try {
    return new URL(origin).host === getRequestHost(req)
  } catch {
    return false
  }
}

function isTrustedOrigin(origin) {
  try {
    const parsedOrigin = new URL(origin)
    return parsedOrigin.protocol === 'https:' && trustedOriginHosts.has(parsedOrigin.host)
  } catch {
    return false
  }
}

function setApiCorsHeaders(req, res) {
  const origin = getRequestOrigin(req)
  if (!origin || isSameOriginRequest(req, origin)) {
    return true
  }

  if (allowAnyCorsOrigin) {
    res.setHeader('Access-Control-Allow-Origin', '*')
  } else if (allowedCorsOrigins.has(origin) || isTrustedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    appendVaryHeader(res, 'Origin')
  } else {
    return false
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,POST,PATCH,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token, Authorization')
  res.setHeader('Access-Control-Max-Age', '600')
  return true
}

function sendJson(res, statusCode, payload) {
  res.statusCode = statusCode
  Object.entries(JSON_HEADERS).forEach(([key, value]) => {
    res.setHeader(key, value)
  })
  res.end(JSON.stringify(payload))
}

function hasJsonContentType(req) {
  const contentType = req.headers['content-type']
  if (typeof contentType !== 'string') return false
  return contentType.toLowerCase().includes('application/json')
}

async function readJsonBody(req) {
  const contentLength = Number(req.headers['content-length'] || 0)
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_SIZE) {
    return { error: 'payload_too_large' }
  }

  let body = ''
  for await (const chunk of req) {
    body += chunk
    if (body.length > MAX_BODY_SIZE) {
      return { error: 'payload_too_large' }
    }
  }

  try {
    return { data: JSON.parse(body || '{}') }
  } catch {
    return { error: 'invalid_json' }
  }
}

function getReviewIdFromPath(pathname) {
  const match = pathname.match(/^\/api\/reviews\/(\d+)$/)
  if (!match) return null

  const reviewId = Number(match[1])
  if (!Number.isInteger(reviewId) || reviewId <= 0) return null
  return reviewId
}

function getAdminTokenFromRequest(req) {
  const headerToken =
    typeof req.headers['x-admin-token'] === 'string' ? req.headers['x-admin-token'].trim() : ''
  if (headerToken) return headerToken

  const authorization = typeof req.headers.authorization === 'string' ? req.headers.authorization : ''
  if (authorization.toLowerCase().startsWith('bearer ')) {
    return authorization.slice(7).trim()
  }

  return ''
}

function isValidAdminToken(providedToken) {
  if (!ADMIN_API_TOKEN || !providedToken) return false

  const expectedBuffer = Buffer.from(ADMIN_API_TOKEN)
  const providedBuffer = Buffer.from(providedToken)

  if (expectedBuffer.length !== providedBuffer.length) {
    return false
  }

  return timingSafeEqual(expectedBuffer, providedBuffer)
}

function requireAdminAccess(req, res) {
  if (!ADMIN_API_TOKEN) {
    sendJson(res, 503, { error: 'Token admin non configure.' })
    return false
  }

  const providedToken = getAdminTokenFromRequest(req)
  if (!isValidAdminToken(providedToken)) {
    sendJson(res, 401, { error: 'Acces admin refuse.' })
    return false
  }

  return true
}

function getClientIp(req) {
  const forwardedFor = req.headers['x-forwarded-for']
  if (typeof forwardedFor === 'string' && forwardedFor.trim()) {
    return forwardedFor.split(',')[0].trim()
  }

  return req.socket.remoteAddress || 'unknown'
}

function enforcePostRateLimit(req, res) {
  const ip = getClientIp(req)
  const now = Date.now()
  const existing = postRateLimitStore.get(ip)

  if (!existing || existing.resetAt <= now) {
    postRateLimitStore.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS })
    return true
  }

  existing.count += 1

  const remaining = Math.max(0, RATE_LIMIT_MAX_POSTS - existing.count)
  const resetAtSeconds = Math.ceil(existing.resetAt / 1000)
  res.setHeader('X-RateLimit-Limit', String(RATE_LIMIT_MAX_POSTS))
  res.setHeader('X-RateLimit-Remaining', String(remaining))
  res.setHeader('X-RateLimit-Reset', String(resetAtSeconds))

  if (existing.count > RATE_LIMIT_MAX_POSTS) {
    const retryAfter = Math.max(1, Math.ceil((existing.resetAt - now) / 1000))
    res.setHeader('Retry-After', String(retryAfter))
    sendJson(res, 429, { error: 'Trop de requetes. Reessayez plus tard.' })
    return false
  }

  return true
}

function stripControlChars(value, { keepNewLines = false } = {}) {
  let output = ''

  for (const char of value) {
    const code = char.charCodeAt(0)
    const isControl = (code >= 0 && code <= 31) || code === 127

    if (!isControl) {
      output += char
      continue
    }

    if (keepNewLines && (char === '\n' || char === '\t')) {
      output += char
    }
  }

  return output
}

function sanitizeSingleLine(value, maxLength) {
  return stripControlChars(String(value ?? '').normalize('NFKC').replace(/\r\n?/g, ' '))
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength)
}

function sanitizeMultiline(value, maxLength) {
  return stripControlChars(String(value ?? '').normalize('NFKC').replace(/\r\n?/g, '\n'), {
    keepNewLines: true,
  })
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
    .slice(0, maxLength)
}

function isValidEmailAddress(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

function normalizeContactPayload(input) {
  const name = sanitizeSingleLine(input?.name, 90)
  const email = sanitizeSingleLine(input?.email, 160).toLowerCase()
  const projectType = sanitizeSingleLine(input?.projectType, 90)
  const budget = sanitizeSingleLine(input?.budget, 90)
  const message = sanitizeMultiline(input?.message, 3_000)

  if (!name || !email || !message || !isValidEmailAddress(email)) {
    return null
  }

  return {
    name,
    email,
    projectType: projectType || 'Non precise',
    budget: budget || 'Non precise',
    message,
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

async function loadNodemailerModule() {
  if (!nodemailerModulePromise) {
    nodemailerModulePromise = import('nodemailer').catch(() => null)
  }

  const moduleNamespace = await nodemailerModulePromise
  if (!moduleNamespace) {
    return null
  }

  return moduleNamespace.default || moduleNamespace
}

async function getContactTransporter() {
  if (contactTransporter) {
    return contactTransporter
  }

  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !CONTACT_FROM_EMAIL || !CONTACT_TO_EMAIL) {
    return null
  }

  const nodemailer = await loadNodemailerModule()
  if (!nodemailer) {
    return null
  }

  contactTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  })

  return contactTransporter
}

async function sendContactEmail(payload) {
  const transporter = await getContactTransporter()
  if (!transporter) {
    return { ok: false, reason: 'not_configured' }
  }

  const submittedAt = new Date().toISOString()
  const subject = `[Site] Nouvelle demande de contact - ${payload.name}`
  const text = [
    'Nouvelle demande depuis le formulaire du site.',
    '',
    `Nom: ${payload.name}`,
    `Email: ${payload.email}`,
    `Type de projet: ${payload.projectType}`,
    `Budget: ${payload.budget}`,
    `Date: ${submittedAt}`,
    '',
    'Message:',
    payload.message,
  ].join('\n')
  const html = `
    <h2>Nouvelle demande depuis le formulaire du site</h2>
    <p><strong>Nom:</strong> ${escapeHtml(payload.name)}</p>
    <p><strong>Email:</strong> ${escapeHtml(payload.email)}</p>
    <p><strong>Type de projet:</strong> ${escapeHtml(payload.projectType)}</p>
    <p><strong>Budget:</strong> ${escapeHtml(payload.budget)}</p>
    <p><strong>Date:</strong> ${escapeHtml(submittedAt)}</p>
    <p><strong>Message:</strong></p>
    <pre style="white-space: pre-wrap; font-family: inherit;">${escapeHtml(payload.message)}</pre>
  `

  await transporter.sendMail({
    from: CONTACT_FROM_EMAIL,
    to: CONTACT_TO_EMAIL,
    replyTo: payload.email,
    subject,
    text,
    html,
  })

  return { ok: true }
}

function resolveStaticFilePath(pathname) {
  let decodedPath = pathname

  try {
    decodedPath = decodeURIComponent(pathname)
  } catch {
    return null
  }

  const normalizedPath = posix.normalize(decodedPath).replace(/^\/+/, '')
  const candidatePath = resolve(DIST_DIR, normalizedPath || 'index.html')
  const distPrefix = DIST_DIR.endsWith(sep) ? DIST_DIR : `${DIST_DIR}${sep}`

  if (candidatePath !== DIST_DIR && !candidatePath.startsWith(distPrefix)) {
    return null
  }

  return candidatePath
}

async function fileExists(pathname) {
  try {
    await access(pathname)
    return true
  } catch {
    return false
  }
}

async function sendFile(req, res, pathname) {
  const extension = extname(pathname).toLowerCase()
  const contentType = MIME_TYPES[extension] || 'application/octet-stream'
  const isHeadRequest = req.method === 'HEAD'

  res.statusCode = 200
  res.setHeader('Content-Type', contentType)
  res.setHeader('Cache-Control', extension === '.html' ? 'no-store' : 'public, max-age=31536000, immutable')

  if (isHeadRequest) {
    res.end()
    return
  }

  createReadStream(pathname).pipe(res)
}

async function handleApi(req, res, store) {
  const pathname = new URL(req.url || '/', 'http://localhost').pathname
  const reviewId = getReviewIdFromPath(pathname)
  const isReviewsCollectionRoute = pathname === '/api/reviews'
  const isReviewItemRoute = reviewId !== null
  const isContactRoute = pathname === '/api/contact'
  if (!isReviewsCollectionRoute && !isReviewItemRoute && !isContactRoute) return false

  if (!setApiCorsHeaders(req, res)) {
    sendJson(res, 403, { error: 'Origine non autorisee.' })
    return true
  }

  if (req.method === 'OPTIONS') {
    const allowMethods = isReviewsCollectionRoute
      ? 'GET,HEAD,POST,OPTIONS'
      : isReviewItemRoute
        ? 'PATCH,DELETE,OPTIONS'
        : 'POST,OPTIONS'
    res.setHeader('Allow', allowMethods)
    res.statusCode = 204
    res.end()
    return true
  }

  if (isReviewsCollectionRoute && req.method === 'HEAD') {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json; charset=utf-8')
    res.end()
    return true
  }

  if (isReviewsCollectionRoute && req.method === 'GET') {
    sendJson(res, 200, { reviews: store.list() })
    return true
  }

  if (isReviewsCollectionRoute && req.method === 'POST') {
    if (!hasJsonContentType(req)) {
      sendJson(res, 415, { error: 'Content-Type application/json requis.' })
      return true
    }

    if (!enforcePostRateLimit(req, res)) {
      return true
    }

    const body = await readJsonBody(req)
    if (body.error === 'payload_too_large') {
      sendJson(res, 413, { error: 'Payload trop volumineux.' })
      return true
    }

    if (body.error === 'invalid_json') {
      sendJson(res, 400, { error: 'Corps JSON invalide.' })
      return true
    }

    const created = store.add(body.data)
    if (!created) {
      sendJson(res, 400, { error: 'Donnees invalides.' })
      return true
    }

    sendJson(res, 201, { review: created })
    return true
  }

  if (isContactRoute && req.method === 'POST') {
    if (!hasJsonContentType(req)) {
      sendJson(res, 415, { error: 'Content-Type application/json requis.' })
      return true
    }

    if (!enforcePostRateLimit(req, res)) {
      return true
    }

    const body = await readJsonBody(req)
    if (body.error === 'payload_too_large') {
      sendJson(res, 413, { error: 'Payload trop volumineux.' })
      return true
    }

    if (body.error === 'invalid_json') {
      sendJson(res, 400, { error: 'Corps JSON invalide.' })
      return true
    }

    const normalizedContact = normalizeContactPayload(body.data)
    if (!normalizedContact) {
      sendJson(res, 400, { error: 'Donnees invalides.' })
      return true
    }

    try {
      const result = await sendContactEmail(normalizedContact)
      if (!result.ok) {
        sendJson(res, 503, { error: 'Service email non configure.' })
        return true
      }
    } catch {
      sendJson(res, 502, { error: "Impossible d'envoyer le message pour le moment." })
      return true
    }

    sendJson(res, 201, { success: true })
    return true
  }

  if (isReviewItemRoute && req.method === 'PATCH') {
    if (!requireAdminAccess(req, res)) {
      return true
    }

    if (!hasJsonContentType(req)) {
      sendJson(res, 415, { error: 'Content-Type application/json requis.' })
      return true
    }

    const body = await readJsonBody(req)
    if (body.error === 'payload_too_large') {
      sendJson(res, 413, { error: 'Payload trop volumineux.' })
      return true
    }

    if (body.error === 'invalid_json') {
      sendJson(res, 400, { error: 'Corps JSON invalide.' })
      return true
    }

    const updated = store.update(reviewId, body.data)
    if (updated === null) {
      sendJson(res, 404, { error: 'Avis introuvable.' })
      return true
    }
    if (updated === false) {
      sendJson(res, 400, { error: 'Donnees invalides.' })
      return true
    }

    sendJson(res, 200, { review: updated })
    return true
  }

  if (isReviewItemRoute && req.method === 'DELETE') {
    if (!requireAdminAccess(req, res)) {
      return true
    }

    const deleted = store.remove(reviewId)
    if (!deleted) {
      sendJson(res, 404, { error: 'Avis introuvable.' })
      return true
    }

    sendJson(res, 200, { success: true })
    return true
  }

  if (isReviewsCollectionRoute) {
    res.setHeader('Allow', 'GET,HEAD,POST,OPTIONS')
  } else if (isReviewItemRoute) {
    res.setHeader('Allow', 'PATCH,DELETE,OPTIONS')
  } else {
    res.setHeader('Allow', 'POST,OPTIONS')
  }
  sendJson(res, 405, { error: 'Methode non autorisee.' })
  return true
}

async function handleStatic(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET,HEAD')
    sendJson(res, 405, { error: 'Methode non autorisee.' })
    return
  }

  const url = new URL(req.url || '/', 'http://localhost')
  let filePath = resolveStaticFilePath(url.pathname)
  if (!filePath) {
    sendJson(res, 400, { error: 'Chemin invalide.' })
    return
  }

  const requestedExtension = extname(url.pathname)

  try {
    const info = await stat(filePath)
    if (info.isDirectory()) {
      filePath = join(filePath, 'index.html')
    }
  } catch {
    if (!requestedExtension) {
      filePath = resolve(DIST_DIR, 'index.html')
    } else {
      sendJson(res, 404, { error: 'Ressource introuvable.' })
      return
    }
  }

  if (!(await fileExists(filePath))) {
    sendJson(res, 500, { error: 'Build manquant. Lancez npm run build.' })
    return
  }

  await sendFile(req, res, filePath)
}

const store = createReviewsStore()

const server = createServer(async (req, res) => {
  setSecurityHeaders(res)

  req.setTimeout(REQUEST_TIMEOUT_MS, () => {
    if (!res.headersSent) {
      sendJson(res, 408, { error: 'Delai de requete depasse.' })
    } else {
      res.destroy()
    }
  })

  try {
    if (await handleApi(req, res, store)) {
      return
    }

    await handleStatic(req, res)
  } catch {
    if (!res.headersSent) {
      sendJson(res, 500, { error: 'Erreur serveur.' })
      return
    }

    res.destroy()
  }
})

server.requestTimeout = REQUEST_TIMEOUT_MS
server.headersTimeout = REQUEST_TIMEOUT_MS + 5_000

server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`)
})

function shutdown() {
  clearInterval(rateLimitSweepTimer)

  try {
    store.close()
  } catch {
    // ignore close errors during shutdown
  }

  try {
    contactTransporter?.close?.()
  } catch {
    // ignore transporter close errors during shutdown
  }

  server.close(() => {
    process.exit(0)
  })
}

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
