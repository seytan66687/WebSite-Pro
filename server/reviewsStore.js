import { mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'

const ROOT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_DB_PATH = resolve(ROOT_DIR, 'data', 'reviews.sqlite')
const DB_PATH = process.env.REVIEWS_DB_PATH
  ? resolve(process.env.REVIEWS_DB_PATH)
  : DEFAULT_DB_PATH

function ensureDir(pathname) {
  mkdirSync(dirname(pathname), { recursive: true })
}

function createDb() {
  ensureDir(DB_PATH)
  const db = new DatabaseSync(DB_PATH)

  db.exec(`
    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      payload TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `)

  return db
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

function normalizeReview(input) {
  const name = sanitizeSingleLine(input?.name, 80)
  const role = sanitizeSingleLine(input?.role, 90) || 'Client'
  const text = sanitizeMultiline(input?.text, 800)
  const rating = Number(input?.rating ?? 0)

  if (!name || !text || !Number.isInteger(rating) || rating < 1 || rating > 5) {
    return null
  }

  return {
    name,
    role,
    text,
    rating,
  }
}

function toRowReview(row) {
  let payload
  try {
    payload = JSON.parse(row.payload)
  } catch {
    return null
  }

  return {
    id: row.id,
    name: payload.name,
    role: payload.role,
    rating: payload.rating,
    text: payload.text,
    createdAt: row.created_at,
  }
}

export function createReviewsStore() {
  const db = createDb()

  const selectStmt = db.prepare('SELECT id, payload, created_at FROM reviews ORDER BY id DESC LIMIT 200')
  const selectByIdStmt = db.prepare('SELECT id, payload, created_at FROM reviews WHERE id = ?')
  const insertStmt = db.prepare('INSERT INTO reviews (payload, created_at) VALUES (?, ?)')
  const updateStmt = db.prepare('UPDATE reviews SET payload = ? WHERE id = ?')
  const deleteStmt = db.prepare('DELETE FROM reviews WHERE id = ?')

  return {
    list() {
      return selectStmt.all().map(toRowReview).filter(Boolean)
    },
    add(input) {
      const normalized = normalizeReview(input)
      if (!normalized) return null

      const createdAt = new Date().toISOString()
      const result = insertStmt.run(JSON.stringify(normalized), createdAt)
      return {
        id: Number(result.lastInsertRowid),
        ...normalized,
        createdAt,
      }
    },
    update(id, input) {
      const numericId = Number(id)
      if (!Number.isInteger(numericId) || numericId <= 0) return null

      const row = selectByIdStmt.get(numericId)
      if (!row) return null

      const current = toRowReview(row)
      if (!current) return null

      const mergedInput = {
        name: input?.name ?? current.name,
        role: input?.role ?? current.role,
        text: input?.text ?? current.text,
        rating: input?.rating ?? current.rating,
      }
      const normalized = normalizeReview(mergedInput)
      if (!normalized) return false

      updateStmt.run(JSON.stringify(normalized), numericId)

      return {
        id: numericId,
        ...normalized,
        createdAt: current.createdAt,
      }
    },
    remove(id) {
      const numericId = Number(id)
      if (!Number.isInteger(numericId) || numericId <= 0) return false

      const result = deleteStmt.run(numericId)
      return Number(result.changes) > 0
    },
    close() {
      db.close()
    },
  }
}
