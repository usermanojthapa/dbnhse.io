/**
 * ==============================================================================
 * HSE FIELD SAFETY PORTAL - GOOGLE APPS SCRIPT BACKEND
 * ==============================================================================
 * Production-ready backend for Work Permit Registration & Safety Observations.
 * Connected to Google Sheets database with atomic locks, audit logging, XSS
 * protection, formula injection prevention, and search/filter/dashboard services.
 * ==============================================================================
 */

// Global Constants for Sheet Names
const CONFIG = {
  SHEETS: {
    WORK_PERMITS: 'Work Permit Records',
    SAFETY_OBSERVATIONS: 'Safety Observations',
    LISTS: 'Lists',
    USERS: 'Users',
    AUDIT_LOG: 'Audit Log',
    SETTINGS: 'Settings',
    IDEMPOTENCY: '_Idempotency',
    WP_ARCHIVE: '_WpArchive'
  },
  PREFIXES: {
    WORK_PERMIT: 'WP',
    SAFETY_OBSERVATION: 'SO'
  },
  LOCK_TIMEOUT_MS: 30000,
  DEFAULT_PAGE_SIZE: 15,
  SESSION_TTL_SECONDS: 8 * 60 * 60, // 8 hours
  CACHE_LISTS_SECONDS: 300,
  MAX_PAGE_SIZE: 100,
  // Canonical schemas (0-based indices)
  WP: {
    COLS: 14, // A–N
    ID: 0, SHIFT: 1, DEPT: 2, SECTION: 3, DATE: 4, WP_NUM: 5, TYPE: 6,
    ACTIVITY: 7, COMMENTS: 8, ISSUER: 9, RECEIVER: 10, CONTRACTOR: 11,
    SPONSOR: 12, STATUS: 13,
    HEADERS: [
      'S.N. / Record ID', 'Shift', 'Department', 'Section / Area', 'WP Date of Issue',
      'Work Permit Number', 'WP Type', 'Activity', 'Comments', 'Issuer Badge Number',
      'Receiver Badge Number', 'Contractor Company', 'Sponsoring Organization', 'Status'
    ]
  },
  SO: {
    COLS: 16, // A–P
    ID: 0, DATE: 1, DEPT: 2, FUNCTION: 3, EQUIP: 4, SECTION: 5, CONTRACTOR: 6,
    SPONSOR: 7, MAIN: 8, TYPE: 9, CATEGORY: 10, ROOT: 11, ACTION: 12,
    STATUS: 13, REPORTED: 14, REPORTED_BY: 15,
    HEADERS: [
      'S.N.', 'Observation Date', 'Department', 'Function / MFT Department', 'Equipment',
      'Section Area', 'PRC Contractor', 'Contractor Sponsoring Organization',
      'Main Safety Observation', 'Unsafe Act / Unsafe Condition', 'Category', 'Root Cause',
      'Safety Representative Interaction / Action Taken', 'Status', 'Reported', 'Reported By'
    ]
  }
};

/**
 * Web App Entry Point - Serves the HTML frontend interface
 */
function doGet(e) {
  return HtmlService.createTemplateFromFile('Index')
    .evaluate()
    .setTitle('DBN L&T HSE | DBN Project Field Safety Portal')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

/**
 * Helper to include HTML fragments if needed
 */
function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

/**
 * Returns active user details safely
 */
function getUserContext() {
  let email = 'Unknown User';
  try {
    email = Session.getActiveUser().getEmail() || Session.getEffectiveUser().getEmail() || 'anonymous@hse-portal.local';
  } catch (err) {
    email = 'anonymous@hse-portal.local';
  }
  return {
    email: email,
    timestamp: new Date().toISOString()
  };
}

// ==============================================================================
// SECURITY: SESSION + RBAC + IDEMPOTENCY
// ==============================================================================

/**
 * Creates a secure session after successful login.
 * Stored in CacheService AND Script Properties (cache can drop under load).
 */
function createSession(userPayload) {
  const token = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
  const body = {
    username: userPayload.username,
    role: userPayload.role,
    roleView: !!userPayload.roleView,
    roleEdit: !!userPayload.roleEdit,
    roleUpload: !!userPayload.roleUpload,
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + (CONFIG.SESSION_TTL_SECONDS * 1000)
  };
  const json = JSON.stringify(body);
  try { CacheService.getScriptCache().put('sess:' + token, json, Math.min(CONFIG.SESSION_TTL_SECONDS, 21600)); } catch (e) {}
  try { PropertiesService.getScriptProperties().setProperty('sess:' + token, json); } catch (e) {}
  return token;
}

function readSessionRecord(token) {
  const key = 'sess:' + token;
  let raw = null;
  try { raw = CacheService.getScriptCache().get(key); } catch (e) {}
  if (!raw) {
    try { raw = PropertiesService.getScriptProperties().getProperty(key); } catch (e) {}
  }
  if (!raw) return null;
  let user;
  try { user = JSON.parse(raw); } catch (e) { return null; }
  if (user.expiresAt && Date.now() > Number(user.expiresAt)) {
    try { CacheService.getScriptCache().remove(key); } catch (e) {}
    try { PropertiesService.getScriptProperties().deleteProperty(key); } catch (e) {}
    return null;
  }
  // Sliding expiry
  user.expiresAt = Date.now() + (CONFIG.SESSION_TTL_SECONDS * 1000);
  const json = JSON.stringify(user);
  try { CacheService.getScriptCache().put(key, json, Math.min(CONFIG.SESSION_TTL_SECONDS, 21600)); } catch (e) {}
  try { PropertiesService.getScriptProperties().setProperty(key, json); } catch (e) {}
  return user;
}

/**
 * Validates session token. Returns { ok, user, response }.
 * required: 'view' | 'upload' | 'edit' | 'admin'
 * Production: no anonymous/ephemeral access — valid session required for all levels.
 */
function requireAuth(sessionToken, required) {
  const token = String(sessionToken || '').trim();
  const need = String(required || 'view').toLowerCase();

  if (!token) {
    return { ok: false, response: createResponse(false, 'Authentication required. Please sign in.', null, 'AUTH_REQUIRED') };
  }

  const user = readSessionRecord(token);
  if (!user) {
    return { ok: false, response: createResponse(false, 'Session expired. Please sign in again.', null, 'SESSION_EXPIRED') };
  }

  // Reject expired sessions even if residual cache exists
  if (user.expiresAt && Number(user.expiresAt) < Date.now()) {
    try { destroySession(token); } catch (e) {}
    return { ok: false, response: createResponse(false, 'Session expired. Please sign in again.', null, 'SESSION_EXPIRED') };
  }

  const role = String(user.role || '').toLowerCase();
  const isAdmin = role === 'super admin' || role === 'admin' ||
    (!!user.roleView && !!user.roleEdit && !!user.roleUpload);
  if (need === 'admin' && !isAdmin) {
    return { ok: false, response: createResponse(false, 'Super Admin access required.', null, 'FORBIDDEN') };
  }
  if (need === 'edit' && !user.roleEdit && !isAdmin) {
    return { ok: false, response: createResponse(false, 'Edit permission required.', null, 'FORBIDDEN') };
  }
  if (need === 'upload' && !user.roleUpload && !user.roleEdit && !isAdmin) {
    return { ok: false, response: createResponse(false, 'Upload permission required.', null, 'FORBIDDEN') };
  }
  if (need === 'view' && user.roleView === false && !isAdmin) {
    return { ok: false, response: createResponse(false, 'View permission required.', null, 'FORBIDDEN') };
  }
  return { ok: true, user: user };
}

/**
 * Login rate limit: max attempts per username+IP-ish key in a window.
 * Uses CacheService only (no sheet writes).
 */
function checkLoginRateLimit(username) {
  const key = 'login_rl:' + String(username || '').toLowerCase().slice(0, 40);
  try {
    const cache = CacheService.getScriptCache();
    const raw = cache.get(key);
    const n = raw ? parseInt(raw, 10) : 0;
    if (n >= 12) {
      return { ok: false, message: 'Too many login attempts. Wait a few minutes and try again.' };
    }
    cache.put(key, String(n + 1), 300); // 5 minute window
  } catch (e) {}
  return { ok: true };
}

function clearLoginRateLimit(username) {
  try {
    CacheService.getScriptCache().remove('login_rl:' + String(username || '').toLowerCase().slice(0, 40));
  } catch (e) {}
}

function destroySession(sessionToken) {
  const token = String(sessionToken || '').trim();
  if (!token) return createResponse(true, 'Logged out');
  const key = 'sess:' + token;
  try { CacheService.getScriptCache().remove(key); } catch (e) {}
  try { PropertiesService.getScriptProperties().deleteProperty(key); } catch (e) {}
  return createResponse(true, 'Logged out');
}

/**
 * Idempotency — indexed lookup (no full-sheet scans on the hot path).
 *
 * Index layers:
 *  1) CacheService  idem:<uuid>           → full JSON (6h)
 *  2) ScriptProps   idem:<uuid>           → full JSON when ≤9KB
 *  3) ScriptProps   idem_row:<uuid>       → sheet row number
 *  4) Sheet row read by index (O(1))
 *  5) Rare rebuild: Text last 200 rows only if index missing
 */
function checkIdempotency(clientUuid) {
  const key = String(clientUuid || '').trim();
  if (!key || key.length > 80) return null;

  // 1) Cache
  try {
    const cached = CacheService.getScriptCache().get('idem:' + key);
    if (cached) {
      try { return JSON.parse(cached); } catch (e) { /* fall through */ }
    }
  } catch (e) {}

  // 2) Properties payload
  try {
    const prop = PropertiesService.getScriptProperties().getProperty('idem:' + key);
    if (prop) {
      try {
        const parsed = JSON.parse(prop);
        try { CacheService.getScriptCache().put('idem:' + key, prop, 21600); } catch (e2) {}
        return parsed;
      } catch (e) {}
    }
  } catch (e) {}

  // 3–4) Indexed sheet row
  try {
    const rowStr = PropertiesService.getScriptProperties().getProperty('idem_row:' + key);
    const row = rowStr ? parseInt(rowStr, 10) : 0;
    if (row >= 2) {
      const ss = SpreadsheetApp.getActiveSpreadsheet();
      const sheet = ensureIdempotencySheet_(ss);
      if (row <= sheet.getLastRow()) {
        const cellKey = String(sheet.getRange(row, 1).getValue() || '');
        if (cellKey === key) {
          const raw = String(sheet.getRange(row, 2).getValue() || '');
          const replay = parseIdempotencyJson_(raw);
          indexIdempotency_(key, replay, row);
          return replay;
        }
      }
    }
  } catch (e) {}

  // 5) Narrow fallback scan (last 200 only) — rebuild index entry if found
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ensureIdempotencySheet_(ss);
    const last = sheet.getLastRow();
    if (last < 2) return null;
    const start = Math.max(2, last - 199);
    const vals = sheet.getRange(start, 1, last, 2).getValues();
    for (let i = vals.length - 1; i >= 0; i--) {
      if (String(vals[i][0]) === key) {
        const replay = parseIdempotencyJson_(String(vals[i][1]));
        indexIdempotency_(key, replay, start + i);
        return replay;
      }
    }
  } catch (e) {}
  return null;
}

function parseIdempotencyJson_(raw) {
  try {
    return JSON.parse(String(raw || ''));
  } catch (e) {
    return { success: true, message: 'Duplicate request ignored', data: null, errorCode: 'IDEMPOTENT_REPLAY' };
  }
}

function indexIdempotency_(key, responseObj, sheetRow) {
  let json;
  try { json = JSON.stringify(responseObj); } catch (e) { return; }
  try { CacheService.getScriptCache().put('idem:' + key, json, 21600); } catch (e) {}
  try {
    if (json.length < 9000) {
      PropertiesService.getScriptProperties().setProperty('idem:' + key, json);
    }
    if (sheetRow >= 2) {
      PropertiesService.getScriptProperties().setProperty('idem_row:' + key, String(sheetRow));
    }
  } catch (e) {}
}

function storeIdempotency(clientUuid, responseObj) {
  const key = String(clientUuid || '').trim();
  if (!key || !responseObj || key.length > 80) return;
  let json;
  try { json = JSON.stringify(responseObj); } catch (e) { return; }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ensureIdempotencySheet_(ss);
    sheet.appendRow([key, json, new Date().toISOString()]);
    const row = sheet.getLastRow();
    indexIdempotency_(key, responseObj, row);
    // Soft retention — prune oldest data rows; index entries expire naturally with props limits
    if (row > 8000) {
      try { sheet.deleteRows(2, Math.min(1000, row - 7000)); } catch (e2) {}
    }
  } catch (e) {
    // Still keep cache/props even if sheet write fails
    indexIdempotency_(key, responseObj, 0);
  }
}

function ensureIdempotencySheet_(ss) {
  let sheet = ss.getSheetByName(CONFIG.SHEETS.IDEMPOTENCY);
  if (!sheet) {
    sheet = ss.insertSheet(CONFIG.SHEETS.IDEMPOTENCY);
    sheet.getRange(1, 1, 1, 3).setValues([['Client UUID', 'Response JSON', 'Timestamp']]);
    sheet.setFrozenRows(1);
    try { sheet.hideSheet(); } catch (e) {}
  }
  return sheet;
}

// ---------- Work Permit archive (system sheet — does NOT touch Comments on WP sheet) ----------

function ensureWpArchiveSheet_(ss) {
  let sheet = ss.getSheetByName(CONFIG.SHEETS.WP_ARCHIVE);
  if (!sheet) {
    sheet = ss.insertSheet(CONFIG.SHEETS.WP_ARCHIVE);
    sheet.getRange(1, 1, 1, 5).setValues([[
      'Record ID', 'Work Permit Number', 'Archived At', 'Archived By', 'Note'
    ]]);
    sheet.setFrozenRows(1);
    try { sheet.hideSheet(); } catch (e) {}
  }
  return sheet;
}

/** Returns a Set of archived WP record IDs (from system sheet + legacy Comments tag). */
function getArchivedWpIdSet(ss, wpDataOptional) {
  const set = {};
  try {
    const arch = ss.getSheetByName(CONFIG.SHEETS.WP_ARCHIVE);
    if (arch && arch.getLastRow() > 1) {
      const vals = arch.getRange(2, 1, arch.getLastRow(), 1).getValues();
      for (let i = 0; i < vals.length; i++) {
        const id = String(vals[i][0] || '').trim();
        if (id) set[id] = true;
      }
    }
  } catch (e) {}

  // Legacy: rows still tagged in Comments before migration
  if (wpDataOptional && wpDataOptional.length > 1) {
    for (let i = 1; i < wpDataOptional.length; i++) {
      const cmt = String(wpDataOptional[i][8] || '');
      if (cmt.indexOf('__ARCHIVED__') !== -1) {
        const id = String(wpDataOptional[i][0] || '').trim();
        if (id) set[id] = true;
      }
    }
  }
  return set;
}

function markWorkPermitArchived_(ss, recordId, wpNumber, archivedBy) {
  const sheet = ensureWpArchiveSheet_(ss);
  const id = String(recordId || '').trim();
  if (!id) return;
  // Avoid duplicate archive rows
  const last = sheet.getLastRow();
  if (last > 1) {
    const ids = sheet.getRange(2, 1, last, 1).getValues();
    for (let i = 0; i < ids.length; i++) {
      if (String(ids[i][0] || '').trim() === id) return;
    }
  }
  sheet.appendRow([
    id,
    String(wpNumber || '').replace(/^'/, ''),
    new Date().toISOString(),
    String(archivedBy || ''),
    'Soft-archived via portal'
  ]);
}

/**
 * One-time migration: move legacy __ARCHIVED__ Comments tags into _WpArchive
 * and strip the tag from Comments (restores original comment text).
 * Does not change WP schema columns — only cell values in Comments.
 */
function migrateLegacyWpArchives() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
  if (!sheet || sheet.getLastRow() <= 1) {
    return createResponse(true, 'No WP rows to migrate.', { migrated: 0 });
  }
  const data = getSheetValues(sheet, CONFIG.WP.COLS);
  let migrated = 0;
  for (let i = 1; i < data.length; i++) {
    const cmt = String(data[i][8] || '');
    if (cmt.indexOf('__ARCHIVED__') === -1) continue;
    const id = String(data[i][0] || '').trim();
    const wpNum = String(data[i][5] || '').replace(/^'/, '');
    markWorkPermitArchived_(ss, id, wpNum, 'migration');
    const cleaned = cmt.replace(/^__ARCHIVED__\s*/, '');
    sheet.getRange(i + 1, 9).setValue(cleaned);
    migrated++;
  }
  logAuditAction('MIGRATE_ARCHIVE', 'Work Permit', '', '', '', 'Migrated ' + migrated + ' legacy archive tags to _WpArchive');
  try { invalidateDashboardCache(); } catch (e) {}
  return createResponse(true, 'Migrated ' + migrated + ' archived permit(s) to system sheet.', { migrated: migrated });
}

/**
 * Batch-read sheet values with optional column limit (avoids full-grid getDataRange when possible).
 */
function getSheetValues(sheet, maxCols) {
  if (!sheet) return [];
  const lastRow = sheet.getLastRow();
  if (lastRow < 1) return [];
  const lastCol = Math.min(sheet.getLastColumn() || 1, maxCols || sheet.getLastColumn() || 1);
  return sheet.getRange(1, 1, lastRow, lastCol).getValues();
}

/**
 * Cached dropdown lists
 */
function getCachedLists() {
  const cache = CacheService.getScriptCache();
  const hit = cache.get('lists:v1');
  if (hit) {
    try { return JSON.parse(hit); } catch (e) {}
  }
  const data = getDropdownListsUncached();
  try { cache.put('lists:v1', JSON.stringify(data), CONFIG.CACHE_LISTS_SECONDS); } catch (e) {}
  return data || {};
}

function invalidateListsCache() {
  try { CacheService.getScriptCache().remove('lists:v1'); } catch (e) {}
}

/**
 * Finds a column index by header name (case-insensitive, partial match allowed).
 * Returns -1 if not found.
 */
function findColumnIndex(headers, candidates) {
  const list = Array.isArray(candidates) ? candidates : [candidates];
  const norm = function (s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, ''); };
  // Pass 1: exact normalized match (preferred)
  for (let c = 0; c < list.length; c++) {
    const want = norm(list[c]);
    if (!want) continue;
    for (let i = 0; i < headers.length; i++) {
      if (norm(headers[i]) === want) return i;
    }
  }
  // Pass 2: header contains full candidate (e.g. "Reported By Name" contains "reportedby")
  for (let c = 0; c < list.length; c++) {
    const want = norm(list[c]);
    if (!want || want.length < 3) continue;
    for (let i = 0; i < headers.length; i++) {
      const h = norm(headers[i]);
      if (h.indexOf(want) !== -1) return i;
    }
  }
  return -1;
}

/**
 * Resolve Safety Observation column map from header row (supports mixed legacy sheets).
 */
function resolveSoColumnMap(headerRow) {
  const h = headerRow || [];
  const map = {
    id: findColumnIndex(h, ['S.N.', 'SN', 'Observation ID', 'Record ID']),
    date: findColumnIndex(h, ['Observation Date', 'Date']),
    dept: findColumnIndex(h, ['Department']),
    function: findColumnIndex(h, ['Function', 'MFT']),
    equip: findColumnIndex(h, ['Equipment']),
    section: findColumnIndex(h, ['Section Area', 'Section']),
    contractor: findColumnIndex(h, ['PRC Contractor', 'Contractor']),
    sponsor: findColumnIndex(h, ['Sponsoring', 'Contractor Sponsoring']),
    main: findColumnIndex(h, ['Main Safety Observation', 'Main Observation', 'Observation']),
    type: findColumnIndex(h, ['Unsafe Act', 'Unsafe Condition', 'Classification']),
    category: findColumnIndex(h, ['Category', 'Safety Category']),
    root: findColumnIndex(h, ['Root Cause', 'Root-Causes', 'Root Causes', 'RootCause', 'Root']),
    action: findColumnIndex(h, ['Action Taken', 'Safety Representative', 'Interaction']),
    status: findColumnIndex(h, ['Status']),
    reported: findColumnIndex(h, ['Reported']),
    reportedBy: -1
  };
  // Exact "Reported By" header (must not match plain "Reported")
  for (let i = 0; i < h.length; i++) {
    const raw = String(h[i] || '').trim().toLowerCase();
    const n = raw.replace(/[^a-z0-9]/g, '');
    if (n === 'reportedby' || raw === 'reported by' || raw === 'reporter' || raw === 'recorder name' || raw === 'recorder') {
      map.reportedBy = i;
      break;
    }
  }
  // Fallbacks to canonical CONFIG indices when header missing
  if (map.id < 0) map.id = CONFIG.SO.ID;
  if (map.date < 0) map.date = CONFIG.SO.DATE;
  if (map.dept < 0) map.dept = CONFIG.SO.DEPT;
  if (map.main < 0) map.main = CONFIG.SO.MAIN;
  if (map.category < 0) map.category = CONFIG.SO.CATEGORY;
  if (map.type < 0) map.type = CONFIG.SO.TYPE;
  if (map.root < 0) map.root = CONFIG.SO.ROOT;
  if (map.status < 0) map.status = CONFIG.SO.STATUS;
  if (map.reportedBy < 0) map.reportedBy = CONFIG.SO.REPORTED_BY; // P = index 15
  return map;
}





// ==============================================================================
// SPREADSHEET INITIALIZATION & CONFIGURATION
// ==============================================================================

/**
 * Automatically creates and initializes all required sheets, headers, formats,
 * and default reference lists. Can be run manually or triggered automatically.
 */
function setupSpreadsheet() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'System is busy setting up database. Please try again.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    
    // Define exact headers for Sheet 1: Work Permit Records
    // Work Permit sheet: columns A–M only (no metadata after M)
    const wpHeaders = CONFIG.WP.HEADERS.slice();

    // Safety Observations — columns match operational sheet (no Shift; no trailing timestamps)
    // A SN | B Date | C Department | D Function/MFT | E Equipment | F Section Area |
    // G Contractor | H Sponsoring Org | I Main Obs | J Type | K Category | L Root Cause |
    // M Action Taken | N Status | O Reported | P Reported By
    const soHeaders = CONFIG.SO.HEADERS.slice();

    // Headers for Audit Log
    const auditHeaders = [
      'Timestamp',
      'User Email',
      'Action',
      'Module',
      'Record ID',
      'Target Ref',
      'Previous Value',
      'New Value',
      'Details'
    ];

    // Headers for Users (4 columns only)
    const userHeaders = ['Username', 'Password', 'Role', 'Status'];

    // Headers for Settings
    const settingHeaders = ['Setting Key', 'Setting Value', 'Description'];

    // 1. Initialize Work Permit Records Sheet
    initSheet(ss, CONFIG.SHEETS.WORK_PERMITS, wpHeaders, [
      { colIndex: 5, format: '@' }, // Work Permit Number as TEXT
      { colIndex: 9, format: '@' }, // Issuer Badge Number as TEXT
      { colIndex: 10, format: '@' } // Receiver Badge Number as TEXT
    ]);

    // 2. Initialize Safety Observations Sheet
    initSheet(ss, CONFIG.SHEETS.SAFETY_OBSERVATIONS, soHeaders, []);

    // 3. Initialize Lists Sheet
    initListsSheet(ss);

    // 4. Initialize Users Sheet (4 columns) + protect sensitive data
    initSheet(ss, CONFIG.SHEETS.USERS, userHeaders, [
      { colIndex: 1, format: '@' } // Password as TEXT
    ]);
    ensureUsersSheetStructure(ss);
    seedDefaultUsers(ss);
    protectUsersSheet(ss);

    // 5. Initialize Audit Log Sheet
    initSheet(ss, CONFIG.SHEETS.AUDIT_LOG, auditHeaders, []);

    // 6. Initialize Settings Sheet
    initSheet(ss, CONFIG.SHEETS.SETTINGS, settingHeaders, []);
    seedDefaultSettings(ss);

    // 7. Idempotency ledger (hidden)
    if (!ss.getSheetByName(CONFIG.SHEETS.IDEMPOTENCY)) {
      const idSheet = ss.insertSheet(CONFIG.SHEETS.IDEMPOTENCY);
      idSheet.getRange(1, 1, 1, 3).setValues([['Client UUID', 'Response JSON', 'Timestamp']]);
      idSheet.hideSheet();
    }

    // Log initialization event
    logAuditAction('SYSTEM_INIT', 'System', 'SYS-001', 'ALL', '', 'Spreadsheet Structure Initialized');

    return createResponse(true, 'Database sheets, headers, and reference lists successfully initialized.');
  } catch (err) {
    Logger.log('Error in setupSpreadsheet: ' + err.toString());
    return createResponse(false, 'Failed to initialize spreadsheet: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Helper to construct a clean sheet with styled headers and column formatting
 */
function initSheet(ss, sheetName, headers, textColumnFormats) {
  let sheet = ss.getSheetByName(sheetName);
  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
  }

  // Ensure header is set cleanly if sheet is empty or has missing columns
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(headers);
  } else {
    // Check if header row matches, if not update line 1
    const currentHeaders = sheet.getRange(1, 1, 1, Math.max(1, sheet.getLastColumn())).getValues()[0];
    if (currentHeaders.length < headers.length || currentHeaders[0] !== headers[0]) {
      sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    }
  }

  // Style Header Row: Dark Slate Header `#1e293b`, Bold White Text `#ffffff`
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  headerRange.setFontWeight('bold')
    .setBackground('#1e293b')
    .setFontColor('#ffffff')
    .setVerticalAlignment('middle')
    .setHorizontalAlignment('center');
  
  sheet.setRowHeight(1, 35);
  sheet.setFrozenRows(1);

  // Apply explicit TEXT format ('@') for specific numeric columns like Badges and WP Numbers
  if (textColumnFormats && textColumnFormats.length > 0) {
    textColumnFormats.forEach(item => {
      const colRange = sheet.getRange(2, item.colIndex + 1, Math.max(100, sheet.getMaxRows()), 1);
      colRange.setNumberFormat(item.format);
    });
  }

  // Clean empty trailing columns if necessary to avoid standard Sheet bloated columns
  const maxCols = sheet.getMaxColumns();
  if (maxCols > headers.length) {
    sheet.deleteColumns(headers.length + 1, maxCols - headers.length);
  }
}

/**
 * Populates default Reference Lists in the 'Lists' sheet cleanly
 */
function initListsSheet(ss) {
  let sheet = ss.getSheetByName(CONFIG.SHEETS.LISTS);
  if (!sheet) {
    sheet = ss.insertSheet(CONFIG.SHEETS.LISTS);
  }

  const listHeaders = [
    'Shift',
    'WP Type',
    'Department',
    'Section Area',
    'Category',
    'Unsafe Act/Condition',
    'Root Cause',
    'Status',
    'Contractor Company',
    'Sponsoring Organization',
    'Function MFT Dept'
  ];

  sheet.getRange(1, 1, 1, listHeaders.length)
    .setValues([listHeaders])
    .setFontWeight('bold')
    .setBackground('#0f172a')
    .setFontColor('#38bdf8')
    .setHorizontalAlignment('center');
  
  sheet.setFrozenRows(1);

  // Seed default data if column 1 is empty
  if (sheet.getLastRow() <= 1) {
    const defaultLists = {
      'Shift': ['Day', 'Night'],
      'WP Type': ['H', 'C', 'CS', 'EOLB'],
      'Department': ['PMD-Monomer I', 'PMD-Monomer II', 'Monomer I', 'Monomer II', 'Polymer', 'Utilities', 'Logistics', 'Maintenance', 'HSE', 'Engineering', 'Offsites & Logistics'],
      'Section Area': ['N200 STF Road F', 'STF 220 N 200', 'STF 220 N 201', 'NAPHTHA', 'R-410 Existing Pipe Rack', 'Tank Farm 1', 'Reactor Area', 'Boiler House', 'Substation 4', 'Warehouse A', 'Loading Rack', 'Utilities Hub'],
      'Category': ['PPE', 'Hot Work', 'Work at Height', 'Electrical Safety', 'Tools & Equipment', 'Housekeeping', 'Line Breaking', 'Fire Protection', 'Environmental', 'Chemical Handling', 'Vehicle Safety'],
      'Unsafe Act/Condition': ['Unsafe Act', 'Unsafe Condition', 'Safe Act / Good Practice'],
      'Root Cause': ['Negligence', 'Inadequate supervision', 'Short Cut', 'Lack of Training', 'Procedure Not Followed', 'Defective Tool/Equipment', 'Poor Housekeeping', 'Fatigue', 'Inadequate PPE', 'Communication Failure'],
      'Status': ['Open', 'In Progress', 'Close', 'Cancelled', 'Active'],
      'Contractor Company': ['L&T-DBN', 'Consolidated Contractors', 'Hyundai Engineering', 'Petrofac', 'Local Subcontractor', 'In-House'],
      'Sponsoring Organization': ['Revamp Projects Execution Department', 'Project Management Department', 'Maintenance Dept', 'Operations Dept', 'HSE Dept', 'Turnaround Dept'],
      'Function MFT Dept': ['Monomer I', 'Monomer II', 'Polymer', 'Utilities', 'HSE', 'Engineering', 'Projects MFT', 'Technical Services MFT']
    };

    // Calculate maximum rows needed
    let maxRows = 0;
    listHeaders.forEach(h => {
      if (defaultLists[h] && defaultLists[h].length > maxRows) {
        maxRows = defaultLists[h].length;
      }
    });

    const matrix = [];
    for (let r = 0; r < maxRows; r++) {
      const row = [];
      listHeaders.forEach(h => {
        const arr = defaultLists[h] || [];
        row.push(arr[r] || '');
      });
      matrix.push(row);
    }

    if (matrix.length > 0) {
      sheet.getRange(2, 1, matrix.length, listHeaders.length).setValues(matrix);
    }
  }

  // Trim columns
  if (sheet.getMaxColumns() > listHeaders.length) {
    sheet.deleteColumns(listHeaders.length + 1, sheet.getMaxColumns() - listHeaders.length);
  }
}

/**
 * Migrates Users sheet to 4-column layout: Username | Password | Role | Status
 * Preserves existing usernames/passwords when possible.
 */
function ensureUsersSheetStructure(ss) {
  let sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  if (!sheet) {
    sheet = ss.insertSheet(CONFIG.SHEETS.USERS);
  }

  const targetHeaders = ['Username', 'Password', 'Role', 'Status'];
  const lastRow = sheet.getLastRow();
  const lastCol = sheet.getLastColumn();

  if (lastRow === 0) {
    sheet.getRange(1, 1, 1, 4).setValues([targetHeaders]);
  } else {
    const headers = sheet.getRange(1, 1, 1, Math.max(lastCol, 1)).getValues()[0].map(h => String(h || '').trim().toLowerCase());
    const isNewLayout = headers[0] === 'username' && headers[1] === 'password' && headers[2] === 'role' && headers[3] === 'status';

    if (!isNewLayout && lastRow >= 1) {
      // Migrate from legacy 8-column layout if present
      const data = sheet.getDataRange().getValues();
      const migrated = [targetHeaders];
      for (let i = 1; i < data.length; i++) {
        const row = data[i];
        if (!row[0]) continue;
        const username = String(row[0]).trim();
        const password = String(row[1] || '').trim().replace(/^'/, '');
        let role = 'Viewer';
        // Legacy: cols 3-5 were Role:View / Role:Edit / Role:Upload
        if (headers.indexOf('role') === 2 && headers.indexOf('status') === 3) {
          role = String(row[2] || 'Viewer').trim() || 'Viewer';
        } else {
          const boolVal = v => v === true || String(v).toLowerCase() === 'true' || String(v) === '1';
          const roleView = boolVal(row[3]);
          const roleEdit = boolVal(row[4]);
          const roleUpload = boolVal(row[5]);
          if (String(username).toLowerCase() === 'admin' || (roleView && roleEdit && roleUpload)) {
            role = 'Super Admin';
          } else if (roleEdit) {
            role = 'Editor';
          } else if (roleUpload) {
            role = 'Uploader';
          } else {
            role = 'Viewer';
          }
        }
        const statusIdx = headers.indexOf('status');
        const status = statusIdx >= 0 ? String(row[statusIdx] || 'Active').trim() : 'Active';
        migrated.push([username, password, role, status || 'Active']);
      }
      sheet.clearContents();
      if (migrated.length > 0) {
        sheet.getRange(1, 1, migrated.length, 4).setValues(migrated);
      }
    } else {
      sheet.getRange(1, 1, 1, 4).setValues([targetHeaders]);
    }
  }

  // Style header
  const headerRange = sheet.getRange(1, 1, 1, 4);
  headerRange.setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff')
    .setVerticalAlignment('middle').setHorizontalAlignment('center');
  sheet.setFrozenRows(1);
  sheet.setRowHeight(1, 35);
  sheet.getRange(2, 2, Math.max(100, sheet.getMaxRows()), 1).setNumberFormat('@');

  // Trim extra columns
  const maxCols = sheet.getMaxColumns();
  if (maxCols > 4) {
    sheet.deleteColumns(5, maxCols - 4);
  }
}

/**
 * Protects the Users sheet so humans cannot freely view/edit passwords in the grid.
 * Script execution still retains access for login & admin APIs.
 */
function protectUsersSheet(ss) {
  try {
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return;

    // Remove prior protections on this sheet to avoid duplicates
    const protections = sheet.getProtections(SpreadsheetApp.ProtectionType.SHEET);
    protections.forEach(p => {
      try { p.remove(); } catch (e) { /* ignore */ }
    });

    const protection = sheet.protect().setDescription('Users sheet — password protected. Manage users only via Super Admin in the portal.');
    protection.setWarningOnly(false);

    // Only the file owner may edit the sheet directly
    const me = Session.getEffectiveUser();
    protection.addEditor(me);
    protection.removeEditors(protection.getEditors().filter(e => e.getEmail() !== me.getEmail()));
    if (protection.canDomainEdit()) {
      protection.setDomainEdit(false);
    }
  } catch (err) {
    Logger.log('protectUsersSheet: ' + err.toString());
  }
}

/**
 * Seeds master admin only when Users sheet has no data rows.
 * Password is a one-time random bootstrap secret (logged to Apps Script Logger only — never returned to clients).
 * Layout: Username | Password (hashed) | Role | Status
 */
function seedDefaultUsers(ss) {
  const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  if (!sheet) return;
  // Only seed when sheet is empty — never overwrite production credentials
  if (sheet.getLastRow() > 1) return;
  const bootstrap = generateBootstrapPassword_();
  sheet.getRange(2, 1, 1, 4).setValues([['admin', hashPassword(bootstrap), 'Super Admin', 'Active']]);
  sheet.getRange(2, 2).setNumberFormat('@');
  // Persist one-time hint on Settings sheet (not Users) for operator recovery after first deploy
  try {
    writeSystemSetting_(ss, 'BOOTSTRAP_ADMIN_HINT', 'Set on ' + new Date().toISOString() + ' — check Script logs for one-time password');
  } catch (e) {}
  Logger.log('SECURITY: Bootstrap admin created. One-time password (change immediately): ' + bootstrap);
}

/** Cryptographically strong-ish bootstrap password (Apps Script Utilities) */
function generateBootstrapPassword_() {
  const bytes = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
  return 'Adm!' + bytes.substring(0, 12);
}

/**
 * Emergency recovery: reset ONLY master admin password to a new random value.
 * Run from Apps Script editor. Password is logged once — never embedded in source.
 * Does not create secondary demo accounts.
 */
function resetMasterAdminPassword() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  if (!sheet) {
    setupSpreadsheet();
    sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  }
  if (!sheet) return createResponse(false, 'Users sheet could not be created.');
  ensureUsersSheetStructure(ss);
  sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);

  const bootstrap = generateBootstrapPassword_();
  const hashed = hashPassword(bootstrap);
  const data = sheet.getDataRange().getValues();
  let found = false;
  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0] || '').trim().toLowerCase() === 'admin') {
      sheet.getRange(i + 1, 2).setValue(hashed).setNumberFormat('@');
      sheet.getRange(i + 1, 3).setValue('Super Admin');
      sheet.getRange(i + 1, 4).setValue('Active');
      found = true;
      break;
    }
  }
  if (!found) {
    sheet.appendRow(['admin', hashed, 'Super Admin', 'Active']);
    sheet.getRange(sheet.getLastRow(), 2).setNumberFormat('@');
  }
  protectUsersSheet(ss);
  logAuditAction('RESET_PASSWORDS', 'Auth', 'admin', '', '', 'Master admin password reset via script editor (random)');
  Logger.log('SECURITY: Master admin password reset. One-time password: ' + bootstrap);
  return createResponse(true, 'Master admin password reset. Open Apps Script → Executions/Logs for the one-time password, then change it after login.');
}

/** @deprecated Use resetMasterAdminPassword — kept as alias without hardcoded secrets */
function resetDefaultPasswords() {
  return resetMasterAdminPassword();
}

function writeSystemSetting_(ss, key, value) {
  let sheet = ss.getSheetByName(CONFIG.SHEETS.SETTINGS);
  if (!sheet) return;
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    if (String(data[i][0] || '') === key) {
      sheet.getRange(i + 1, 2).setValue(String(value));
      return;
    }
  }
  sheet.appendRow([key, String(value), 'System']);
}

/**
 * Maps Role column value → permission flags used by the frontend.
 */
function roleToPermissions(role) {
  const r = String(role || '').trim().toLowerCase();
  if (r === 'super admin' || r === 'admin' || r === 'superadmin') {
    return { roleView: true, roleEdit: true, roleUpload: true, roleLabel: 'Super Admin' };
  }
  if (r === 'editor') {
    return { roleView: true, roleEdit: true, roleUpload: false, roleLabel: 'Editor' };
  }
  if (r === 'uploader') {
    return { roleView: true, roleEdit: false, roleUpload: true, roleLabel: 'Uploader' };
  }
  // Viewer / default
  return { roleView: true, roleEdit: false, roleUpload: false, roleLabel: 'Viewer' };
}

// ==============================================================================
// PASSWORD HASHING (salted SHA-256)
// Storage format: v1$<saltHex>$<sha256Hex>
// ==============================================================================

/**
 * Generates a cryptographically stronger hex salt (16 bytes → 32 hex chars).
 * Uses Utilities.getUuid entropy (not Math.random).
 */
function generateSalt() {
  // Two UUIDs → 64 hex chars of entropy; take 32 for salt field
  const a = Utilities.getUuid().replace(/-/g, '');
  const b = Utilities.getUuid().replace(/-/g, '');
  // Mix with digest for uniform distribution
  return sha256Hex(a + b + String(Date.now())).substring(0, 32);
}

/**
 * SHA-256 digest of a string → lowercase hex.
 */
function sha256Hex(str) {
  const raw = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(str), Utilities.Charset.UTF_8);
  return raw.map(function (b) {
    const v = (b < 0) ? b + 256 : b;
    return ('0' + v.toString(16)).slice(-2);
  }).join('');
}

/**
 * Returns true if the stored value looks like a hashed password.
 */
function isPasswordHashed(stored) {
  return /^v1\$[0-9a-f]{32}\$[0-9a-f]{64}$/i.test(String(stored || '').trim());
}

/**
 * Hashes a plaintext password with a new random salt.
 * @returns {string} v1$salt$hash
 */
function hashPassword(plainPassword) {
  const salt = generateSalt();
  const digest = sha256Hex(salt + String(plainPassword));
  return 'v1$' + salt + '$' + digest;
}

/**
 * Verifies a plaintext password against a stored value.
 * Supports:
 *  - hashed form v1$salt$hash
 *  - legacy plaintext (exact match) for migration
 */
function verifyPassword(plainPassword, storedValue) {
  const stored = String(storedValue || '').trim().replace(/^'/, '');
  const plain = String(plainPassword || '');
  if (!stored || plain === '') return false;

  if (isPasswordHashed(stored)) {
    const parts = stored.split('$');
    // parts: ['v1', salt, hash]
    if (parts.length !== 3) return false;
    const salt = parts[1];
    const expected = parts[2].toLowerCase();
    const actual = sha256Hex(salt + plain);
    return actual === expected;
  }

  // Legacy plaintext
  return stored === plain;
}

/**
 * If stored password is still plaintext and matches, upgrade it to a hash in-place.
 * @returns {string|null} new hash if upgraded, otherwise null
 */
function upgradePasswordHashIfNeeded(sheet, rowIndex1Based, plainPassword, storedValue) {
  const stored = String(storedValue || '').trim().replace(/^'/, '');
  if (isPasswordHashed(stored)) return null;
  if (stored !== String(plainPassword || '')) return null;
  const hashed = hashPassword(plainPassword);
  sheet.getRange(rowIndex1Based, 2).setValue(hashed).setNumberFormat('@');
  return hashed;
}

/**
 * Verifies the MASTER user "admin" password only (not other Super Admins).
 * Used for privileged user-management actions.
 */
function confirmAdminPassword(adminPassword) {
  return confirmMasterAdminPassword(adminPassword);
}

/**
 * Master account only: username must be exactly "admin".
 */
function confirmMasterAdminPassword(adminPassword) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  if (!sheet || sheet.getLastRow() <= 1) return false;
  const cleanPass = String(adminPassword || '').trim().replace(/^'/, '');
  if (!cleanPass) return false;
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    const uname = String(data[i][0] || '').trim().toLowerCase();
    if (uname !== 'admin') continue;
    const stored = String(data[i][1] || '').trim().replace(/^'/, '');
    const status = String(data[i][3] || '').trim().toLowerCase();
    if (status && status !== 'active') continue;
    if (verifyPassword(cleanPass, stored)) {
      upgradePasswordHashIfNeeded(sheet, i + 1, cleanPass, stored);
      return true;
    }
  }
  return false;
}

/** True if username is the protected master account */
function isMasterAdminUsername(username) {
  return String(username || '').trim().toLowerCase() === 'admin';
}

/**
 * Seeds default key-value system settings
 */
function seedDefaultSettings(ss) {
  const sheet = ss.getSheetByName(CONFIG.SHEETS.SETTINGS);
  if (sheet && sheet.getLastRow() <= 1) {
    const defaultSettings = [
      ['APP_NAME', 'HSE Field Safety Portal', 'Application Title'],
      ['WP_ID_PREFIX', '', 'Deprecated — Work Permit serials are plain numbers only'],
      ['SO_ID_PREFIX', 'SO-', 'Prefix for Safety Observation IDs'],
      ['CHECK_DUPLICATE_PERMITS', 'TRUE', 'Check duplicate WP # + Date on submission'],
      ['REQUIRE_BADGE_NUMBERS', 'TRUE', 'Enforce badge number formatting'],
      ['DEFAULT_PAGE_SIZE', '15', 'Records per page in search tables']
    ];
    sheet.getRange(2, 1, defaultSettings.length, 3).setValues(defaultSettings);
  }
}

// ==============================================================================
// REFERENCE LISTS & CONFIG READERS
// ==============================================================================

/**
 * Fetches dynamic dropdown options from the 'Lists' sheet
 */
function getDropdownLists(sessionToken) {
  try {
    return createResponse(true, 'Dropdown reference lists fetched successfully', getCachedLists());
  } catch (err) {
    return createResponse(false, 'Failed to read dropdown lists: ' + err.message);
  }
}

function getDropdownListsUncached() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(CONFIG.SHEETS.LISTS);
  if (!sheet) {
    setupSpreadsheet();
    sheet = ss.getSheetByName(CONFIG.SHEETS.LISTS);
  }
  if (!sheet) return {};
  const data = getSheetValues(sheet, 30);
  if (data.length <= 1) return {};
  const headers = data[0];
  const result = {};
  headers.forEach(function (h, colIdx) {
    if (!h) return;
    const options = [];
    for (let r = 1; r < data.length; r++) {
      const val = data[r][colIdx];
      if (val !== undefined && val !== null && String(val).trim() !== '') {
        options.push(String(val).trim());
      }
    }
    result[String(h)] = options;
  });
  return result;
}

/**
 * Adds a new option to a specific list in the 'Lists' sheet
 */
function addListValue(listName, newValue) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'System busy. Try again.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.LISTS);
    if (!sheet) return createResponse(false, 'Lists sheet not found');

    const cleanVal = sanitizeInput(newValue);
    if (!cleanVal) return createResponse(false, 'Value cannot be empty');

    const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    const colIdx = headers.indexOf(listName);

    if (colIdx === -1) {
      return createResponse(false, `List '${listName}' does not exist.`);
    }

    // Find first empty cell in column or append below last row
    const colValues = sheet.getRange(1, colIdx + 1, sheet.getLastRow(), 1).getValues();
    let targetRow = colValues.length + 1;

    for (let i = 1; i < colValues.length; i++) {
      if (!colValues[i][0] || String(colValues[i][0]).trim() === '') {
        targetRow = i + 1;
        break;
      }
    }

    sheet.getRange(targetRow, colIdx + 1).setValue(cleanVal);
    logAuditAction('ADD_LIST_OPTION', 'Lists', listName, cleanVal, '', `Added option '${cleanVal}' to list '${listName}'`);

    invalidateListsCache();
    return createResponse(true, `Option '${cleanVal}' added to list '${listName}' successfully.`);
  } catch (err) {
    return createResponse(false, 'Failed to add option: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

// ==============================================================================
// MODULE A: WORK PERMIT REGISTRATION
// ==============================================================================

/**
 * Records an existing Work Permit entry into Sheet 1: Work Permit Records
 */
function submitWorkPermitRecord(formData) {
  formData = formData || {};
  const auth = requireAuth(formData.sessionToken, 'upload');
  if (!auth.ok) return auth.response;

  const clientUuid = String(formData.clientUuid || '').trim();
  if (clientUuid) {
    const prior = checkIdempotency(clientUuid);
    if (prior) return prior;
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy recording data. Please try submitting again in a moment.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    if (!sheet) {
      setupSpreadsheet();
      sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    }

    // 1. Server-side Sanitization & Validation
    const shift = sanitizeInput(formData.shift);
    const department = sanitizeInput(formData.department);
    const section = sanitizeInput(formData.section);
    const wpDateRaw = sanitizeInput(formData.wpDateOfIssue);
    const wpDate = formatDateMDY(wpDateRaw); // store as mm/dd/yyyy like observation sheet
    const wpNumber = sanitizeInput(formData.workPermitNumber);
    const wpType = sanitizeInput(formData.wpType);
    const activity = sanitizeInput(formData.activity);
    const comments = sanitizeInput(formData.comments);
    const issuerBadge = formatBadgeNumber(formData.issuerBadgeNumber);
    const receiverBadge = formatBadgeNumber(formData.receiverBadgeNumber);
    const contractor = sanitizeInput(formData.contractorCompany);
    const sponsoringOrg = sanitizeInput(formData.sponsoringOrganization);

    // Basic required field assertions
    if (!wpNumber || !wpDate || !department || !shift || !wpType) {
      return createResponse(false, 'Please fill in all mandatory fields: Shift, Department, WP Date, WP Number, WP Type.');
    }

    // 2. Duplicate: same WP Number + same Shift (different shift is allowed)
    const checkDuplicate = getSettingValue('CHECK_DUPLICATE_PERMITS') !== 'FALSE';
    if (checkDuplicate && sheet.getLastRow() > 1) {
      const existingRows = sheet.getDataRange().getValues();
      for (let i = 1; i < existingRows.length; i++) {
        const rowWPNum = String(existingRows[i][5] || '').replace(/^'/, '').trim();
        const rowShift = String(existingRows[i][1] || '').trim();
        const rowStatus = String(existingRows[i].length > 13 ? (existingRows[i][13] || '') : '').trim();
        if (rowStatus === 'Cancelled' || rowStatus === 'Archived') continue;
        if (rowWPNum === wpNumber && rowShift.toLowerCase() === String(shift).toLowerCase()) {
          return createResponse(false, 'Permit already submitted', null, 'DUPLICATE_PERMIT');
        }
      }
    }

    // Autofill defaults when UI fields are hidden
    const contractorFinal = contractor || 'L&T-DBN';
    const sponsoringFinal = sponsoringOrg || 'Project Management Department';
    const commentsFinal = comments || 'No Infraction';

    // 3. Plain auto serial only (1, 2, 3…) — never WP-YYYY-#####
    const recordId = String(generateNextPlainSerial(sheet));
    const userContext = getUserContext();
    const timestampStr = formatTimestamp(new Date());

    // 4. Columns A–M only (13 cols) — nothing recorded after column M
    const newRow = [
      recordId,           // A  plain serial
      shift,              // B
      department,         // C
      section,            // D
      wpDate,             // E
      "'" + wpNumber,     // F
      wpType,             // G
      activity,           // H
      commentsFinal,      // I
      "'" + issuerBadge,  // J
      "'" + receiverBadge,// K
      contractorFinal,    // L
      sponsoringFinal     // M
    ];

    sheet.appendRow(newRow);
    const newRowIndex = sheet.getLastRow();

    // Format painter: copy properties from the SN=1 data row (fallback: row 2)
    try {
      applyFormatFromSerialOne(sheet, newRowIndex, 13);
    } catch (fmtErr) {
      Logger.log('WP format copy: ' + fmtErr);
    }

    // Column A = plain number serial; date E as mm/dd/yyyy; text cols as text
    try {
      sheet.getRange(newRowIndex, 1).setNumberFormat('0').setValue(Number(recordId) || recordId);
      sheet.getRange(newRowIndex, 5).setNumberFormat('m/d/yyyy').setValue(wpDate);
    } catch (e) {}
    sheet.getRange(newRowIndex, 6).setNumberFormat('@');   // F WP #
    sheet.getRange(newRowIndex, 10).setNumberFormat('@');  // J Issuer
    sheet.getRange(newRowIndex, 11).setNumberFormat('@');  // K Receiver

    // Re-apply format painter AFTER value/format overrides so SN=1 styles stick
    try {
      applyFormatFromSerialOne(sheet, newRowIndex, 13);
      sheet.getRange(newRowIndex, 1).setNumberFormat('0');
      sheet.getRange(newRowIndex, 5).setNumberFormat('m/d/yyyy');
      sheet.getRange(newRowIndex, 6).setNumberFormat('@');
      sheet.getRange(newRowIndex, 10).setNumberFormat('@');
      sheet.getRange(newRowIndex, 11).setNumberFormat('@');
    } catch (e) {}

    // From column N onward: clear content + white background
    try {
      clearTrailingColumnsWhite(sheet, newRowIndex, 14); // col N = 14
    } catch (e) {}

    // 5. Audit Log
    logAuditAction('CREATE', 'Work Permit', recordId, wpNumber, '', `Work Permit #${wpNumber} registered by ${userContext.email}`);

    const okRes = createResponse(true, 'Work Permit Record Created Successfully!', {
      recordId: recordId,
      workPermitNumber: wpNumber,
      dateOfIssue: wpDate,
      timestamp: timestampStr,
      status: 'Active',
      clientUuid: clientUuid || null
    });
    if (clientUuid) storeIdempotency(clientUuid, okRes);
    try { invalidateDashboardCache(); } catch (eInv) {}
    return okRes;

  } catch (err) {
    Logger.log('Error in submitWorkPermitRecord: ' + err.toString());
    return createResponse(false, 'Failed to record Work Permit: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Updates an existing Work Permit row by recordId.
 */
function updateWorkPermitRecord(formData) {
  formData = formData || {};
  const auth = requireAuth(formData.sessionToken, 'edit');
  if (!auth.ok) return auth.response;
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy. Please try again.');
  }
  try {
    const recordId = String((formData && formData.recordId) || '').trim();
    if (!recordId) return createResponse(false, 'Record ID is required.');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(false, 'Work Permit sheet not found.');

    const data = sheet.getDataRange().getValues();
    let targetRow = -1;
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === recordId) {
        targetRow = i + 1;
        break;
      }
    }
    if (targetRow < 0) return createResponse(false, 'Record not found: ' + recordId);

    const shift = sanitizeInput(formData.shift);
    const department = sanitizeInput(formData.department);
    const section = sanitizeInput(formData.section);
    const wpDate = formatDateMDY(sanitizeInput(formData.wpDateOfIssue));
    const wpNumber = sanitizeInput(formData.workPermitNumber);
    const wpType = sanitizeInput(formData.wpType);
    const activity = sanitizeInput(formData.activity);
    const comments = sanitizeInput(formData.comments);
    const issuerBadge = formatBadgeNumber(formData.issuerBadgeNumber);
    const receiverBadge = formatBadgeNumber(formData.receiverBadgeNumber);
    const contractor = sanitizeInput(formData.contractorCompany);
    const sponsoringOrg = sanitizeInput(formData.sponsoringOrganization);
    if (!wpNumber || !wpDate || !department || !shift || !wpType) {
      return createResponse(false, 'Please fill in all mandatory fields.');
    }

    // Update columns B–M only (nothing after M)
    sheet.getRange(targetRow, 2, 1, 12).setValues([[
      shift, department, section, wpDate,
      "'" + wpNumber, wpType, activity, comments || '',
      "'" + issuerBadge, "'" + receiverBadge,
      contractor || '', sponsoringOrg || ''
    ]]);
    // Format painter from SN=1 row, then enforce critical number formats
    try {
      applyFormatFromSerialOne(sheet, targetRow, 13);
      sheet.getRange(targetRow, 5).setNumberFormat('m/d/yyyy');
      sheet.getRange(targetRow, 6).setNumberFormat('@');
      sheet.getRange(targetRow, 10).setNumberFormat('@');
      sheet.getRange(targetRow, 11).setNumberFormat('@');
      clearTrailingColumnsWhite(sheet, targetRow, 14);
    } catch (e) {}

    logAuditAction('UPDATE', 'Work Permit', recordId, wpNumber, '', `Work Permit ${recordId} updated`);
    return createResponse(true, 'Work Permit updated successfully.', { recordId: recordId });
  } catch (err) {
    return createResponse(false, 'Failed to update Work Permit: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Deletes a Work Permit row by recordId.
 */
/**
 * Archives (soft-deletes) a Work Permit. Permanent delete only via purgeWorkPermitRecord (Super Admin).
 * @param {string|Object} recordIdOrPayload - id string or {recordId, sessionToken, hardDelete}
 */
function deleteWorkPermitRecord(recordIdOrPayload, maybeToken) {
  let recordId, sessionToken, hardDelete = false;
  if (recordIdOrPayload && typeof recordIdOrPayload === 'object') {
    recordId = recordIdOrPayload.recordId;
    sessionToken = recordIdOrPayload.sessionToken;
    hardDelete = !!recordIdOrPayload.hardDelete;
  } else {
    recordId = recordIdOrPayload;
    sessionToken = maybeToken;
  }
  const auth = requireAuth(sessionToken, hardDelete ? 'admin' : 'edit');
  if (!auth.ok) return auth.response;

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy. Please try again.');
  }
  try {
    const id = String(recordId || '').trim();
    if (!id) return createResponse(false, 'Record ID is required.');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(false, 'Work Permit sheet not found.');

    const data = getSheetValues(sheet, CONFIG.WP.COLS);
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === id) {
        const wpNumber = String(data[i][CONFIG.WP.WP_NUM] || '').replace(/^'/, '');
        if (hardDelete && String(auth.user.role).toLowerCase().indexOf('super') !== -1) {
          sheet.deleteRow(i + 1);
          logAuditAction('PURGE', 'Work Permit', id, wpNumber, 'Active', 'Permanently deleted by Super Admin');
          return createResponse(true, 'Work Permit permanently deleted.');
        }
        // Soft-archive via system sheet _WpArchive (Comments field left unchanged)
        markWorkPermitArchived_(ss, id, wpNumber, auth.user && auth.user.username);
        try { invalidateDashboardCache(); } catch (eInv) {}
        logAuditAction('ARCHIVE', 'Work Permit', id, wpNumber, 'Active', 'Archived');
        return createResponse(true, 'Work Permit archived successfully.');
      }
    }
    return createResponse(false, 'Record not found: ' + id);
  } catch (err) {
    return createResponse(false, 'Failed to archive Work Permit: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

// ==============================================================================
// MODULE B: SAFETY OBSERVATIONS
// ==============================================================================

/**
 * Records a new HSE Safety Observation into Sheet 2: Safety Observations
 */
function submitSafetyObservationRecord(formData) {
  formData = formData || {};
  const auth = requireAuth(formData.sessionToken, 'upload');
  if (!auth.ok) return auth.response;

  const clientUuid = String(formData.clientUuid || '').trim();
  if (clientUuid) {
    const prior = checkIdempotency(clientUuid);
    if (prior) return prior;
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy recording observation. Please try again.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet) {
      setupSpreadsheet();
      sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    }

    // 1. Server-side Sanitization & Validation
    const obsDateRaw = sanitizeInput(formData.observationDate);
    const department = sanitizeInput(formData.department);
    const functionDept = sanitizeInput(formData.functionMftDept);
    const sectionArea = sanitizeInput(formData.sectionArea);
    const equipment = sanitizeInput(formData.equipment);
    const prcContractor = sanitizeInput(formData.prcContractor);
    const contractorSponsoringOrg = sanitizeInput(formData.contractorSponsoringOrg);
    const mainObservation = sanitizeInput(formData.mainSafetyObservation);
    const unsafeType = sanitizeInput(formData.unsafeActCondition);
    let category = sanitizeInput(formData.category);
    const rootCause = sanitizeInput(formData.rootCause);
    const actionTaken = sanitizeInput(formData.actionTaken);
    let status = sanitizeInput(formData.status) || 'Open';
    if (String(status).toLowerCase() === 'close') status = 'Closed';
    const reported = sanitizeInput(formData.reported);
    const reportedBy = sanitizeInput(formData.reportedBy) || getUserContext().email;

    // Auto-classify from observation text (never fails the submission)
    let classification = null;
    try {
      classification = classifyObservation(mainObservation);
      // If user left category empty, use primary from engine
      if (!category && classification && classification.primaryLabel) {
        category = classification.primaryLabel;
      }
    } catch (classErr) {
      Logger.log('classifyObservation error (non-fatal): ' + classErr);
      classification = null;
    }
    if (!category) category = 'Unclassified';

    // Required field validation (category may come from auto-classify)
    if (!obsDateRaw || !department || !mainObservation || !unsafeType || !category) {
      return createResponse(false, 'Please fill in required fields: Date, Department, Category, Observation Type, and Main Observation description.');
    }

    // Date as mm/dd/yyyy to match existing sheet style
    const obsDate = formatDateMDY(obsDateRaw);

    // 2. Sequential SN from last observation count (e.g. 1074 after 1073)
    const obsId = generateNextPlainSerial(sheet);
    const userContext = getUserContext();

    // 3. Row matches operational sheet layout (16 columns A–P) — NO Shift, NO timestamps
    // A SN | B Date | C Department | D Function/MFT | E Equipment | F Section Area |
    // G Contractor | H Sponsoring | I Main | J Type | K Category | L Root |
    // M Action | N Status | O Reported | P Reported By
    const newRow = [
      obsId,                                              // A plain serial
      obsDate,                                            // B
      department,                                         // C
      functionDept || 'PMD-Monomer II',                   // D
      equipment || '',                                    // E
      sectionArea || '',                                  // F
      prcContractor || 'L&T-DBN',                         // G
      contractorSponsoringOrg || 'Project Management Department', // H
      mainObservation,                                    // I
      unsafeType,                                         // J
      category,                                           // K
      rootCause || '',                                    // L Root Cause
      actionTaken || '',                                  // M
      status,                                             // N
      reported || 'L&T',                                  // O
      reportedBy || ''                                    // P
    ];

    sheet.appendRow(newRow);
    const newRowIndex = sheet.getLastRow();

    // Format painter from SN=1, then enforce serial + date formats
    try {
      applyFormatFromSerialOne(sheet, newRowIndex, 16);
      sheet.getRange(newRowIndex, 1).setNumberFormat('0').setValue(Number(obsId) || obsId);
      sheet.getRange(newRowIndex, 2).setNumberFormat('m/d/yyyy');
      clearTrailingColumnsWhite(sheet, newRowIndex, 17); // col Q = 17
    } catch (e) {}

    // 4. Audit Log
    const matchedIds = (classification && classification.matchedCategories) ? classification.matchedCategories : [];
    logAuditAction(
      'CREATE',
      'Safety Observation',
      String(obsId),
      String(obsId),
      '',
      `Observation ${obsId} (${unsafeType} - ${category}) created by ${userContext.email}` +
        (matchedIds.length ? `; autoCategories=[${matchedIds.join(',')}]` : '')
    );

    const okRes = createResponse(true, 'Safety Observation Recorded Successfully', {
      observationId: String(obsId),
      date: obsDate,
      category: category,
      type: unsafeType,
      status: status,
      primaryCategory: classification ? classification.primaryCategory : null,
      matchedCategories: matchedIds,
      timestamp: formatTimestamp(new Date()),
      clientUuid: clientUuid || null
    });
    if (clientUuid) storeIdempotency(clientUuid, okRes);
    try { invalidateDashboardCache(); } catch (eInv) {}
    return okRes;

  } catch (err) {
    Logger.log('Error in submitSafetyObservationRecord: ' + err.toString());
    return createResponse(false, 'Failed to record Safety Observation: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}


/**
 * Updates a Safety Observation by observationId.
 */
function updateSafetyObservationRecord(formData) {
  formData = formData || {};
  const auth = requireAuth(formData.sessionToken, 'edit');
  if (!auth.ok) return auth.response;
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy. Please try again.');
  }
  try {
    const obsId = String((formData && formData.observationId) || '').trim();
    if (!obsId) return createResponse(false, 'Observation ID is required.');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(false, 'Safety Observations sheet not found.');

    const data = sheet.getDataRange().getValues();
    let targetRow = -1;
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === obsId) {
        targetRow = i + 1;
        break;
      }
    }
    if (targetRow < 0) return createResponse(false, 'Record not found: ' + obsId);

    const obsDate = sanitizeInput(formData.observationDate);
    const department = sanitizeInput(formData.department);
    const sectionArea = sanitizeInput(formData.sectionArea);
    const mainObservation = sanitizeInput(formData.mainSafetyObservation);
    const actionTaken = sanitizeInput(formData.actionTaken);
    const status = sanitizeInput(formData.status) || String(data[targetRow - 1][CONFIG.SO.STATUS] || 'Open');
    const reportedBy = sanitizeInput(formData.reportedBy) || String(data[targetRow - 1][CONFIG.SO.REPORTED_BY] || '');

    const functionDept = sanitizeInput(formData.functionMftDept);
    const equipment = sanitizeInput(formData.equipment);
    const prcContractor = sanitizeInput(formData.prcContractor);
    const contractorSponsoringOrg = sanitizeInput(formData.contractorSponsoringOrg);
    const unsafeType = sanitizeInput(formData.unsafeActCondition);
    const category = sanitizeInput(formData.category);
    const rootCause = sanitizeInput(formData.rootCause);
    const reported = sanitizeInput(formData.reported);

    if (obsDate) {
      sheet.getRange(targetRow, 2).setValue(formatDateMDY(obsDate));
      try { sheet.getRange(targetRow, 2).setNumberFormat('m/d/yyyy'); } catch (e) {}
    }
    if (department) sheet.getRange(targetRow, 3).setValue(department);
    sheet.getRange(targetRow, 4).setValue(functionDept || 'PMD-Monomer II');
    if (equipment !== undefined && equipment !== null) sheet.getRange(targetRow, 5).setValue(equipment || '');
    if (sectionArea) sheet.getRange(targetRow, 6).setValue(sectionArea);
    sheet.getRange(targetRow, 7).setValue(prcContractor || 'L&T-DBN');
    sheet.getRange(targetRow, 8).setValue(contractorSponsoringOrg || 'Project Management Department');
    if (mainObservation) sheet.getRange(targetRow, 9).setValue(mainObservation);
    if (unsafeType) sheet.getRange(targetRow, 10).setValue(unsafeType);
    if (category) sheet.getRange(targetRow, 11).setValue(category);
    if (rootCause !== undefined && rootCause !== null) sheet.getRange(targetRow, 12).setValue(rootCause || '');
    if (actionTaken !== undefined && actionTaken !== null) sheet.getRange(targetRow, 13).setValue(actionTaken);
    sheet.getRange(targetRow, 14).setValue(status);
    sheet.getRange(targetRow, 15).setValue(reported || 'L&T');
    if (reportedBy) sheet.getRange(targetRow, 16).setValue(reportedBy);

    // Format painter from SN=1 row + white beyond column P
    try {
      applyFormatFromSerialOne(sheet, targetRow, 16);
      clearTrailingColumnsWhite(sheet, targetRow, 17);
    } catch (e) {}

    logAuditAction('UPDATE', 'Safety Observation', obsId, obsId, '', 'Observation updated via UI');
    return createResponse(true, 'Safety Observation updated successfully.', { observationId: obsId });
  } catch (err) {
    return createResponse(false, 'Failed to update observation: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Deletes a Safety Observation by observationId.
 */
function deleteSafetyObservationRecord(observationIdOrPayload, maybeToken) {
  let obsId, sessionToken, hardDelete = false;
  if (observationIdOrPayload && typeof observationIdOrPayload === 'object') {
    obsId = observationIdOrPayload.observationId || observationIdOrPayload.recordId;
    sessionToken = observationIdOrPayload.sessionToken;
    hardDelete = !!observationIdOrPayload.hardDelete;
  } else {
    obsId = observationIdOrPayload;
    sessionToken = maybeToken;
  }
  const auth = requireAuth(sessionToken, hardDelete ? 'admin' : 'edit');
  if (!auth.ok) return auth.response;

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy. Please try again.');
  }
  try {
    const id = String(obsId || '').trim();
    if (!id) return createResponse(false, 'Observation ID is required.');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(false, 'Safety Observations sheet not found.');

    const data = getSheetValues(sheet, CONFIG.SO.COLS);
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === id) {
        if (hardDelete) {
          sheet.deleteRow(i + 1);
          logAuditAction('PURGE', 'Safety Observation', id, id, '', 'Permanently deleted by Super Admin');
          return createResponse(true, 'Observation permanently deleted.');
        }
        const prev = String(data[i][CONFIG.SO.STATUS] || '');
        sheet.getRange(i + 1, CONFIG.SO.STATUS + 1).setValue('Archived');
        logAuditAction('ARCHIVE', 'Safety Observation', id, id, prev, 'Archived');
        return createResponse(true, 'Observation archived successfully.');
      }
    }
    return createResponse(false, 'Record not found: ' + id);
  } catch (err) {
    return createResponse(false, 'Failed to archive observation: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}


// ==============================================================================
// SEARCH, FILTER & PAGINATION SERVICES
// ==============================================================================

/**
 * Searches and paginates Work Permit Records
 */
function getWorkPermitRecords(params) {
  params = params || {};
  const auth = requireAuth(params.sessionToken, 'view');
  if (!auth.ok) return auth.response;
  try {
    params = params || {};
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    if (!sheet) return createResponse(true, 'No records found', { records: [], total: 0, page: 1 });

    const rawData = getSheetValues(sheet, CONFIG.WP.COLS);
    if (rawData.length <= 1) {
      return createResponse(true, 'No records found', { records: [], total: 0, page: 1 });
    }

    const archivedSet = getArchivedWpIdSet(ss, rawData);
    let rows = [];

    for (let i = 1; i < rawData.length; i++) {
      const r = rawData[i];
      const cmt = String(r[8] || '');
      const rid = String(r[0] || '');
      const isArchived = !!archivedSet[rid] ||
        (r.length > 13 && String(r[13] || '').trim().toLowerCase() === 'archived');
      rows.push({
        recordId: rid,
        shift: String(r[1] || ''),
        department: String(r[2] || ''),
        section: String(r[3] || ''),
        wpDateOfIssue: formatDateMDY(r[4]),
        workPermitNumber: String(r[5] || '').replace(/^'/, ''),
        wpType: String(r[6] || ''),
        activity: String(r[7] || ''),
        comments: cmt.replace(/^__ARCHIVED__\s*/, ''),
        issuerBadgeNumber: String(r[9] || '').replace(/^'/, ''),
        receiverBadgeNumber: String(r[10] || '').replace(/^'/, ''),
        contractorCompany: String(r[11] || ''),
        sponsoringOrganization: String(r[12] || ''),
        createdDateTime: '',
        createdBy: '',
        lastUpdatedDateTime: '',
        status: isArchived ? 'Archived' : 'Active'
      });
    }

    // Filter Logic
    const query = (params.search || '').toLowerCase().trim();
    const dept = (params.department || '').trim();
    const shift = (params.shift || '').trim();
    const wpType = (params.wpType || '').trim();
    const status = (params.status || '').trim();
    const startDate = params.startDate || '';
    const endDate = params.endDate || '';
    const issuerBadge = String(params.issuerBadge || '').trim().toLowerCase();
    const receiverBadge = String(params.receiverBadge || '').trim().toLowerCase();

    let filtered = rows.filter(item => {
      if (!params.includeArchived && String(item.status || '').toLowerCase() === 'archived') return false;
      if (status && item.status !== status) return false;
      if (dept && item.department !== dept) return false;
      if (shift && String(item.shift || '').toLowerCase().indexOf(String(shift).toLowerCase()) === -1) return false;
      if (wpType && item.wpType !== wpType) return false;
      const itemDate = toSortableDate(item.wpDateOfIssue);
      if (startDate && itemDate && itemDate < toSortableDate(startDate)) return false;
      if (endDate && itemDate && itemDate > toSortableDate(endDate)) return false;
      if (issuerBadge && !String(item.issuerBadgeNumber || '').toLowerCase().includes(issuerBadge)) return false;
      if (receiverBadge && !String(item.receiverBadgeNumber || '').toLowerCase().includes(receiverBadge)) return false;

      if (query) {
        const text = `${item.recordId} ${item.workPermitNumber} ${item.activity} ${item.section} ${item.contractorCompany} ${item.issuerBadgeNumber} ${item.receiverBadgeNumber}`.toLowerCase();
        if (!text.includes(query)) return false;
      }
      return true;
    });

    // Sort by date DESC, then SN DESC
    filtered.sort((a, b) => compareByDateThenSerial(
      a.wpDateOfIssue, b.wpDateOfIssue, a.recordId, b.recordId
    ));

    // Pagination
    const page = parseInt(params.page, 10) || 1;
    const pageSize = parseInt(params.pageSize, 10) || CONFIG.DEFAULT_PAGE_SIZE;
    const totalRecords = filtered.length;
    const totalPages = Math.ceil(totalRecords / pageSize) || 1;
    const startIndex = (page - 1) * pageSize;
    const paginatedRecords = filtered.slice(startIndex, startIndex + pageSize);

    return createResponse(true, 'Records fetched', {
      records: paginatedRecords,
      total: totalRecords,
      page: page,
      totalPages: totalPages,
      pageSize: pageSize
    });
  } catch (err) {
    Logger.log('Error in getWorkPermitRecords: ' + err.toString());
    return createResponse(false, 'Failed to fetch Work Permit records: ' + err.message);
  }
}

/**
 * Searches and paginates Safety Observation Records
 */
function getSafetyObservationRecords(params) {
  params = params || {};
  const auth = requireAuth(params.sessionToken, 'view');
  if (!auth.ok) return auth.response;
  try {
    params = params || {};
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet) return createResponse(true, 'No records found', { records: [], total: 0, page: 1 });

    const rawData = getSheetValues(sheet, Math.max(CONFIG.SO.COLS, 16));
    if (rawData.length <= 1) {
      return createResponse(true, 'No records found', { records: [], total: 0, page: 1 });
    }

    let rows = [];
    const soMap = resolveSoColumnMap(rawData[0] || []);
    const idxId = soMap.id >= 0 ? soMap.id : CONFIG.SO.ID;
    const idxDate = soMap.date >= 0 ? soMap.date : CONFIG.SO.DATE;
    const idxDept = soMap.dept >= 0 ? soMap.dept : CONFIG.SO.DEPT;
    const idxFn = soMap.function >= 0 ? soMap.function : CONFIG.SO.FUNCTION;
    const idxSec = soMap.section >= 0 ? soMap.section : CONFIG.SO.SECTION;
    const idxEq = soMap.equip >= 0 ? soMap.equip : CONFIG.SO.EQUIP;
    const idxCo = soMap.contractor >= 0 ? soMap.contractor : CONFIG.SO.CONTRACTOR;
    const idxSp = soMap.sponsor >= 0 ? soMap.sponsor : CONFIG.SO.SPONSOR;
    const idxMain = soMap.main >= 0 ? soMap.main : CONFIG.SO.MAIN;
    const idxType = soMap.type >= 0 ? soMap.type : CONFIG.SO.TYPE;
    const idxCat = soMap.category >= 0 ? soMap.category : CONFIG.SO.CATEGORY;
    const idxRoot = soMap.root >= 0 ? soMap.root : CONFIG.SO.ROOT;
    const idxAct = soMap.action >= 0 ? soMap.action : CONFIG.SO.ACTION;
    const idxSt = soMap.status >= 0 ? soMap.status : CONFIG.SO.STATUS;
    const idxRep = soMap.reported >= 0 ? soMap.reported : CONFIG.SO.REPORTED;
    const idxBy = soMap.reportedBy >= 0 ? soMap.reportedBy : CONFIG.SO.REPORTED_BY;

    for (let i = 1; i < rawData.length; i++) {
      const r = rawData[i];
      let reportedByVal = String(r[idxBy] != null ? r[idxBy] : '').trim();
      if (reportedByVal === 'true' || reportedByVal === 'false') reportedByVal = '';
      rows.push({
        observationId: String(r[idxId] != null ? r[idxId] : ''),
        observationDate: formatDateMDY(r[idxDate]),
        shift: '',
        functionMftDept: String(r[idxFn] != null ? r[idxFn] : ''),
        department: String(r[idxDept] != null ? r[idxDept] : ''),
        sectionArea: String(r[idxSec] != null ? r[idxSec] : ''),
        equipment: String(r[idxEq] != null ? r[idxEq] : ''),
        prcContractor: String(r[idxCo] != null ? r[idxCo] : ''),
        contractorSponsoringOrg: String(r[idxSp] != null ? r[idxSp] : ''),
        mainSafetyObservation: String(r[idxMain] != null ? r[idxMain] : ''),
        unsafeActCondition: String(r[idxType] != null ? r[idxType] : ''),
        category: String(r[idxCat] != null ? r[idxCat] : ''),
        rootCause: String(r[idxRoot] != null ? r[idxRoot] : ''),
        actionTaken: String(r[idxAct] != null ? r[idxAct] : ''),
        followUp: '',
        status: String(r[idxSt] != null ? r[idxSt] : ''),
        reported: String(r[idxRep] != null ? r[idxRep] : ''),
        reportedBy: reportedByVal,
        createdDateTime: '',
        lastUpdatedDateTime: ''
      });
    }

    // Filters
    const query = (params.search || '').toLowerCase().trim();
    const dept = (params.department || '').trim();
    const category = (params.category || '').trim();
    const unsafeType = (params.unsafeType || '').trim();
    const status = (params.status || '').trim();
    const startDate = params.startDate || '';
    const endDate = params.endDate || '';
    const reportedBy = String(params.reportedBy || '').trim().toLowerCase();

    let filtered = rows.filter(item => {
      if (!params.includeArchived && String(item.status || '').toLowerCase() === 'archived') return false;
      if (status && item.status !== status) return false;
      if (dept && item.department !== dept) return false;
      if (category && item.category !== category) return false;
      if (unsafeType && item.unsafeActCondition !== unsafeType) return false;
      const itemDate = toSortableDate(item.observationDate);
      if (startDate && itemDate && itemDate < toSortableDate(startDate)) return false;
      if (endDate && itemDate && itemDate > toSortableDate(endDate)) return false;
      if (reportedBy && !String(item.reportedBy || '').toLowerCase().includes(reportedBy)) return false;

      if (query) {
        const text = `${item.observationId} ${item.mainSafetyObservation} ${item.actionTaken} ${item.sectionArea} ${item.prcContractor} ${item.rootCause} ${item.reportedBy}`.toLowerCase();
        if (!text.includes(query)) return false;
      }
      return true;
    });

    // Sort by date DESC, then SN DESC
    filtered.sort((a, b) => compareByDateThenSerial(
      a.observationDate, b.observationDate, a.observationId, b.observationId
    ));

    // Pagination
    const page = parseInt(params.page, 10) || 1;
    const pageSize = parseInt(params.pageSize, 10) || CONFIG.DEFAULT_PAGE_SIZE;
    const totalRecords = filtered.length;
    const totalPages = Math.ceil(totalRecords / pageSize) || 1;
    const startIndex = (page - 1) * pageSize;
    const paginatedRecords = filtered.slice(startIndex, startIndex + pageSize);

    return createResponse(true, 'Observations fetched', {
      records: paginatedRecords,
      total: totalRecords,
      page: page,
      totalPages: totalPages,
      pageSize: pageSize
    });
  } catch (err) {
    Logger.log('Error in getSafetyObservationRecords: ' + err.toString());
    return createResponse(false, 'Failed to fetch Safety Observations: ' + err.message);
  }
}

// ==============================================================================
// UPDATE & STATUS CHANGE SERVICES
// ==============================================================================

/**
 * Updates status of a Work Permit or Safety Observation
 */
function updateRecordStatus(moduleName, recordId, newStatus, comments) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'System busy. Please try again.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheetName = moduleName === 'Work Permit' ? CONFIG.SHEETS.WORK_PERMITS : CONFIG.SHEETS.SAFETY_OBSERVATIONS;
    let sheet = ss.getSheetByName(sheetName);

    if (!sheet) return createResponse(false, 'Target sheet not found.');

    const data = sheet.getDataRange().getValues();
    let targetRowIndex = -1;
    let oldStatus = '';
    let statusColIndex = moduleName === 'Work Permit' ? 17 : 16; // 1-based index
    let updatedColIndex = moduleName === 'Work Permit' ? 16 : 20;

    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]) === recordId) {
        targetRowIndex = i + 1;
        oldStatus = String(data[i][statusColIndex - 1]);
        break;
      }
    }

    if (targetRowIndex === -1) {
      return createResponse(false, `Record ID '${recordId}' not found.`);
    }

    const nowStr = formatTimestamp(new Date());
    sheet.getRange(targetRowIndex, statusColIndex).setValue(newStatus);
    sheet.getRange(targetRowIndex, updatedColIndex).setValue(nowStr);

    const user = getUserContext().email;
    logAuditAction('UPDATE_STATUS', moduleName, recordId, recordId, oldStatus, `Status changed to '${newStatus}' by ${user}. Notes: ${comments || 'N/A'}`);

    return createResponse(true, `Status for ${recordId} updated to '${newStatus}' successfully.`);
  } catch (err) {
    Logger.log('Error in updateRecordStatus: ' + err.toString());
    return createResponse(false, 'Failed to update record: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

// ==============================================================================
// DASHBOARD STATISTICS SERVICE
// ==============================================================================

/**
 * Returns {start,end} YYYY-MM-DD for dashboard period filter.
 * period: today | yesterday | weekly | monthly | total
 */
function getDashboardPeriodRange(period) {
  const p = String(period || 'total').toLowerCase().trim();
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayStr = formatDateValue(today);

  if (p === 'today') return { start: todayStr, end: todayStr };

  if (p === 'yesterday') {
    const y = new Date(today);
    y.setDate(y.getDate() - 1);
    const ys = formatDateValue(y);
    return { start: ys, end: ys };
  }

  if (p === 'weekly') {
    const s = new Date(today);
    s.setDate(s.getDate() - 6);
    return { start: formatDateValue(s), end: todayStr };
  }

  if (p === 'monthly') {
    const s = new Date(today);
    s.setDate(s.getDate() - 29);
    return { start: formatDateValue(s), end: todayStr };
  }

  return { start: '', end: '' }; // total — no date filter
}

function isDateInRange(dateStr, start, end) {
  if (!dateStr) return false;
  if (start && dateStr < start) return false;
  if (end && dateStr > end) return false;
  return true;
}

/** Normalize reporter label for comparison */
function normalizeReporterKey(name) {
  return String(name || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Title-case a display name */
function titleCaseReporter(name) {
  return String(name || '')
    .trim()
    .replace(/\s+/g, ' ')
    .split(' ')
    .filter(Boolean)
    .map(function (w) {
      return w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
    })
    .join(' ');
}

/**
 * True if two reporter names refer to the same person.
 * Handles: "Manoj" / "Manoj Thapa" / "manoj thapa" / "thapa"
 */
function reportersAreSamePerson(a, b) {
  const na = normalizeReporterKey(a);
  const nb = normalizeReporterKey(b);
  if (!na || !nb) return false;
  if (na === nb) return true;

  const ta = na.split(' ').filter(Boolean);
  const tb = nb.split(' ').filter(Boolean);
  if (!ta.length || !tb.length) return false;

  // Shorter token set fully contained in longer (order-independent)
  const shorter = ta.length <= tb.length ? ta : tb;
  const longer = ta.length <= tb.length ? tb : ta;
  if (shorter.every(function (t) { return longer.indexOf(t) !== -1; })) {
    return true;
  }

  // Single-token name matches first or last name of multi-token name
  if (ta.length === 1 && tb.length > 1) {
    return tb[0] === ta[0] || tb[tb.length - 1] === ta[0];
  }
  if (tb.length === 1 && ta.length > 1) {
    return ta[0] === tb[0] || ta[ta.length - 1] === tb[0];
  }

  // Same first + last when both have 2+ tokens (middle names optional)
  if (ta.length >= 2 && tb.length >= 2) {
    if (ta[0] === tb[0] && ta[ta.length - 1] === tb[tb.length - 1]) return true;
  }

  return false;
}

/**
 * Merge raw reporter counts so name variants become one leaderboard line.
 * Display name prefers the longest, best-formed variant.
 */
function mergeReporterNameCounts(rawMap) {
  const entries = [];
  Object.keys(rawMap || {}).forEach(function (name) {
    const count = Number(rawMap[name]) || 0;
    if (!count || !String(name || '').trim()) return;
    entries.push({ name: String(name).trim(), count: count });
  });

  const groups = []; // { display, count, members[] }

  entries.forEach(function (entry) {
    let matched = null;
    for (let g = 0; g < groups.length; g++) {
      if (reportersAreSamePerson(entry.name, groups[g].display) ||
          groups[g].members.some(function (m) { return reportersAreSamePerson(entry.name, m); })) {
        matched = groups[g];
        break;
      }
    }
    if (matched) {
      matched.count += entry.count;
      matched.members.push(entry.name);
      // Prefer longer / multi-word display name
      const cur = matched.display;
      const next = entry.name;
      if (next.length > cur.length ||
          (next.split(/\s+/).length > cur.split(/\s+/).length && next.length >= cur.length - 2)) {
        matched.display = next;
      }
    } else {
      groups.push({ display: entry.name, count: entry.count, members: [entry.name] });
    }
  });

  // Second pass: merge groups that match each other (handles A~B, B~C chaining)
  let merged = true;
  while (merged) {
    merged = false;
    for (let i = 0; i < groups.length; i++) {
      for (let j = i + 1; j < groups.length; j++) {
        const same =
          reportersAreSamePerson(groups[i].display, groups[j].display) ||
          groups[i].members.some(function (mi) {
            return groups[j].members.some(function (mj) {
              return reportersAreSamePerson(mi, mj);
            });
          });
        if (same) {
          groups[i].count += groups[j].count;
          groups[i].members = groups[i].members.concat(groups[j].members);
          if (groups[j].display.length > groups[i].display.length) {
            groups[i].display = groups[j].display;
          }
          groups.splice(j, 1);
          merged = true;
          break;
        }
      }
      if (merged) break;
    }
  }

  const out = {};
  groups.forEach(function (g) {
    out[titleCaseReporter(g.display)] = g.count;
  });
  return out;
}

/**
 * Aggregates high-level metrics for the HSE Dashboard.
 * @param {string} period - today | yesterday | weekly | monthly | total
 */
function getDashboardStats(period, sessionToken) {
  // period may be object {period, sessionToken} from client
  let shiftFilter = 'Both';
  if (period && typeof period === 'object') {
    sessionToken = period.sessionToken;
    shiftFilter = String(period.shift || 'Both');
    period = period.period;
  }
  const auth = requireAuth(sessionToken, 'view');
  if (!auth.ok) return auth.response;

  const periodKey = String(period || 'total');
  const shiftKey = String(shiftFilter || 'Both');
  const cacheKey = 'dash:v7rc:' + periodKey + ':' + shiftKey;
  try {
    const cached = CacheService.getScriptCache().get(cacheKey);
    if (cached) {
      const parsed = JSON.parse(cached);
      if (parsed && parsed.success) return parsed;
    }
  } catch (eCache) {}

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const wpSheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    const soSheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);

    const todayStr = formatDateValue(new Date());
    const range = getDashboardPeriodRange(period);
    const filterByPeriod = !!(range.start || range.end);
    const shiftNeed = String(shiftFilter || 'Both').toLowerCase();

    // --- Work Permits Aggregations (bounded columns only) ---
    let totalWp = 0;
    let todayWp = 0;
    let dayShiftWp = 0;
    let nightShiftWp = 0;
    const wpByDept = {};
    const wpByType = {};
    const wpDaily = {};
    const wpByStatus = {};
    const wpByTypeStatus = {};

    if (wpSheet && wpSheet.getLastRow() > 1) {
      const wpData = getSheetValues(wpSheet, CONFIG.WP.COLS);
      const archivedSet = getArchivedWpIdSet(ss, wpData);
      for (let i = 1; i < wpData.length; i++) {
        const row = wpData[i];
        const rid = String(row[0] || '').trim();
        if (archivedSet[rid]) continue;
        if (row.length > 13 && String(row[13] || '').trim().toLowerCase() === 'archived') continue;

        const dateStr = formatDateValue(row[4]);
        // Shift column may be "Night", "NIGHT", "Day", "DAY" (CSV has mixed case)
        const shiftLower = String(row[1] || '').toLowerCase();
        const isDay = shiftLower.indexOf('day') !== -1;
        const isNight = shiftLower.indexOf('night') !== -1;

        // Apply shift filter BEFORE Today KPI and period totals
        if (shiftNeed === 'day' && !isDay) continue;
        if (shiftNeed === 'night' && !isNight) continue;

        if (dateStr === todayStr) todayWp++;
        if (filterByPeriod && !isDateInRange(dateStr, range.start, range.end)) continue;

        totalWp++;
        const dept = String(row[2] || '') || 'Unassigned';
        const type = String(row[6] || '') || 'Other';
        // Read existing Status column (N / index 13) — do not hard-code Active
        let status = String(row[CONFIG.WP.STATUS] != null ? row[CONFIG.WP.STATUS] : (row[13] || '')).trim();
        if (!status) status = 'Active';
        const statusLower = status.toLowerCase();
        if (statusLower === 'archived') continue;
        // Normalize common variants for KPI grouping
        if (statusLower === 'close' || statusLower === 'completed' || statusLower === 'complete') status = 'Closed';
        else if (statusLower === 'canceled') status = 'Cancelled';
        else if (statusLower === 'active' || statusLower === 'open') status = status.charAt(0).toUpperCase() + status.slice(1).toLowerCase();

        if (isDay) dayShiftWp++;
        if (isNight) nightShiftWp++;

        wpByDept[dept] = (wpByDept[dept] || 0) + 1;
        wpByType[type] = (wpByType[type] || 0) + 1;
        wpByStatus[status] = (wpByStatus[status] || 0) + 1;
        if (!wpByTypeStatus[type]) wpByTypeStatus[type] = {};
        wpByTypeStatus[type][status] = (wpByTypeStatus[type][status] || 0) + 1;
        if (dateStr) wpDaily[dateStr] = (wpDaily[dateStr] || 0) + 1;
      }
    }

    // --- Safety Observations Aggregations (fast path: sheet Category column, no NLP per row) ---
    let totalSo = 0;
    let todaySo = 0;
    let openSo = 0;
    let closedSo = 0;
    let unsafeActs = 0;
    let unsafeConditions = 0;
    const soByCategory = {};
    const soByDept = {};
    const soDaily = {};
    let soByReporter = {};
    const soByRootCause = {};

    if (soSheet && soSheet.getLastRow() > 1) {
      const soData = getSheetValues(soSheet, Math.max(CONFIG.SO.COLS, 16));
      const soMap = resolveSoColumnMap(soData[0] || []);
      const reporterCol = soMap.reportedBy >= 0 ? soMap.reportedBy : CONFIG.SO.REPORTED_BY;
      const statusIdx = soMap.status >= 0 ? soMap.status : CONFIG.SO.STATUS;
      const deptIdx = soMap.dept >= 0 ? soMap.dept : CONFIG.SO.DEPT;
      const typeIdx = soMap.type >= 0 ? soMap.type : CONFIG.SO.TYPE;
      const catIdx = soMap.category >= 0 ? soMap.category : CONFIG.SO.CATEGORY;
      const rootIdx = soMap.root >= 0 ? soMap.root : CONFIG.SO.ROOT;
      const dateIdx = soMap.date >= 0 ? soMap.date : CONFIG.SO.DATE;
      const mainIdx = soMap.main >= 0 ? soMap.main : CONFIG.SO.MAIN;
      // Optional Shift column (if present on sheet) — does not require schema change
      const shiftIdx = findColumnIndex(soData[0] || [], ['Shift', 'WP Shift', 'Observation Shift']);

      for (let i = 1; i < soData.length; i++) {
        const row = soData[i];
        const status = String(row[statusIdx] || '');
        if (status.toLowerCase() === 'archived') continue;

        // Apply shift filter when a Shift column exists (reporter leaderboard + SO KPIs)
        if (shiftIdx >= 0 && shiftNeed !== 'both') {
          const soShift = String(row[shiftIdx] || '').toLowerCase();
          if (shiftNeed === 'day' && soShift.indexOf('day') === -1) continue;
          if (shiftNeed === 'night' && soShift.indexOf('night') === -1) continue;
        }

        const dateStr = formatDateValue(row[dateIdx]);
        // Today KPI only after shift filter (when available)
        if (dateStr === todayStr) todaySo++;
        if (filterByPeriod && !isDateInRange(dateStr, range.start, range.end)) continue;

        totalSo++;

        if (status === 'Open' || status === 'In Progress') openSo++;
        else if (status === 'Closed' || status === 'Close') closedSo++;

        const unsafeType = String(row[typeIdx] || '');
        const ut = unsafeType.toLowerCase();
        if (ut.indexOf('act') !== -1) unsafeActs++;
        if (ut.indexOf('condition') !== -1) unsafeConditions++;

        // Fast: use Category column (classification runs at submit time)
        const sheetCategory = String(row[catIdx] || '') || 'General';
        soByCategory[sheetCategory] = (soByCategory[sheetCategory] || 0) + 1;

        const dept = String(row[deptIdx] || '') || 'Unassigned';
        soByDept[dept] = (soByDept[dept] || 0) + 1;

        // Analytics-only evidence classification (sheet Root-Causes never rewritten)
        const rootRaw = String(row[rootIdx] || '').trim();
        const mainText = String(row[mainIdx] != null ? row[mainIdx] : '');
        const classified = classifyRootCauseEvidence(rootRaw, mainText, unsafeType, sheetCategory);
        let rootStd = classified.label;
        if (ROOT_CAUSE_STANDARD_LABELS.indexOf(rootStd) === -1) rootStd = 'Other';
        soByRootCause[rootStd] = (soByRootCause[rootStd] || 0) + 1;

        if (dateStr) soDaily[dateStr] = (soDaily[dateStr] || 0) + 1;

        if (reporterCol >= 0 && reporterCol < row.length) {
          const val = row[reporterCol];
          if (typeof val !== 'boolean' && val !== null && val !== undefined) {
            const s = String(val).trim();
            if (s && s.length < 80 && !/^(false|true|null|undefined|unassigned|n\/?a|-)$/i.test(s)) {
              soByReporter[s] = (soByReporter[s] || 0) + 1;
            }
          }
        }
      }
    }

    soByReporter = mergeReporterNameCounts(soByReporter);

    // Final guard: byRootCause may only contain standardized labels
    Object.keys(soByRootCause).forEach(function (k) {
      if (ROOT_CAUSE_STANDARD_LABELS.indexOf(k) === -1) {
        soByRootCause['Other'] = (soByRootCause['Other'] || 0) + (soByRootCause[k] || 0);
        delete soByRootCause[k];
      }
    });

    const response = createResponse(true, 'Dashboard metrics calculated successfully', {
      period: periodKey,
      range: range,
      workPermits: {
        total: totalWp,
        today: todayWp,
        dayShift: dayShiftWp,
        nightShift: nightShiftWp,
        byDepartment: wpByDept,
        byType: wpByType,
        byStatus: wpByStatus,
        byTypeStatus: wpByTypeStatus,
        daily: wpDaily
      },
      safetyObservations: {
        total: totalSo,
        today: todaySo,
        open: openSo,
        closed: closedSo,
        unsafeActs: unsafeActs,
        unsafeConditions: unsafeConditions,
        byCategory: soByCategory,
        byDepartment: soByDept,
        byRootCause: soByRootCause,
        daily: soDaily,
        byReporter: soByReporter
      },
      lastUpdated: formatTimestamp(new Date())
    });

    try {
      CacheService.getScriptCache().put(cacheKey, JSON.stringify(response), 120); // 120s cache
    } catch (ePut) {}

    return response;

  } catch (err) {
    Logger.log('Error in getDashboardStats: ' + err.toString());
    return createResponse(false, 'Failed to compile dashboard metrics: ' + err.message);
  }
}

/** Clear dashboard cache after data changes */
function invalidateDashboardCache() {
  try {
    const cache = CacheService.getScriptCache();
    const periods = ['today', 'yesterday', 'weekly', 'monthly', 'total'];
    const shifts = ['Both', 'Day', 'Night', 'both', 'day', 'night'];
    periods.forEach(function (p) {
      shifts.forEach(function (s) {
        try { cache.remove('dash:v7rc:' + p + ':' + s); } catch (e) {}
        try { cache.remove('dash:v6rc:' + p + ':' + s); } catch (e) {}
        try { cache.remove('dash:v5:' + p + ':' + s); } catch (e) {}
        try { cache.remove('dash:v4:' + p + ':' + s); } catch (e) {}
        try { cache.remove('dash:v3:' + p + ':' + s); } catch (e) {}
        try { cache.remove('dash:v2:' + p + ':' + s); } catch (e) {}
      });
    });
  } catch (e) {}
}

// ==============================================================================
// OBSERVATION CATEGORY CLASSIFICATION ENGINE
// Observation text → normalize → weighted phrase/keyword match → multi-category
// → primary selection → idempotent counting (per observation, not per keyword)
// ==============================================================================

/**
 * Centralized category dictionary.
 * keywords: { phrase, weight } — higher weight = more specific.
 * IDs are stable; labels are for display / sheet Category column.
 */
const OBSERVATION_CATEGORIES = {
  PPE: {
    label: 'PPE',
    priority: 1,
    keywords: [
      { phrase: 'full body harness', weight: 5 }, { phrase: 'safety glasses', weight: 5 },
      { phrase: 'face shield', weight: 5 }, { phrase: 'safety helmet', weight: 5 },
      { phrase: 'hard hat', weight: 5 }, { phrase: 'safety gloves', weight: 5 },
      { phrase: 'hand gloves', weight: 5 }, { phrase: 'safety shoes', weight: 5 },
      { phrase: 'safety boots', weight: 5 }, { phrase: 'ear protection', weight: 5 },
      { phrase: 'hearing protection', weight: 5 }, { phrase: 'reflective vest', weight: 5 },
      { phrase: 'fr coverall', weight: 5 }, { phrase: 'fire resistant clothing', weight: 5 },
      { phrase: 'dust mask', weight: 4 }, { phrase: 'ear plug', weight: 4 },
      { phrase: 'ear plugs', weight: 4 }, { phrase: 'respirator', weight: 4 },
      { phrase: 'ppe compliance', weight: 4 }, { phrase: 'ppe violation', weight: 4 },
      { phrase: 'missing ppe', weight: 4 }, { phrase: 'improper ppe', weight: 4 },
      { phrase: 'incorrect ppe', weight: 4 }, { phrase: 'damaged ppe', weight: 4 },
      { phrase: 'helmet', weight: 4 }, { phrase: 'goggles', weight: 4 },
      { phrase: 'gloves', weight: 3 }, { phrase: 'harness', weight: 3 },
      { phrase: 'ppe', weight: 2 }, { phrase: 'mask', weight: 1 }
    ]
  },
  SCAFFOLDING: {
    label: 'Scaffolding & Ladders',
    priority: 2,
    keywords: [
      { phrase: 'scaffold inspection tag', weight: 5 }, { phrase: 'scaffold inspection', weight: 5 },
      { phrase: 'unauthorized scaffold modification', weight: 5 }, { phrase: 'incomplete scaffold', weight: 5 },
      { phrase: 'damaged scaffold', weight: 5 }, { phrase: 'extension ladder', weight: 5 },
      { phrase: 'step ladder', weight: 5 }, { phrase: 'portable ladder', weight: 5 },
      { phrase: 'access ladder', weight: 5 }, { phrase: 'scaffold platform', weight: 5 },
      { phrase: 'scaffold tag', weight: 5 }, { phrase: 'toe board', weight: 5 },
      { phrase: 'mid rail', weight: 4 }, { phrase: 'guardrail', weight: 4 },
      { phrase: 'handrail', weight: 4 }, { phrase: 'green tag', weight: 4 },
      { phrase: 'red tag', weight: 3 }, { phrase: 'yellow tag', weight: 3 },
      { phrase: 'ladder angle', weight: 4 }, { phrase: 'ladder footing', weight: 4 },
      { phrase: 'ladder support', weight: 4 }, { phrase: 'scaffold access', weight: 4 },
      { phrase: 'scaffold stability', weight: 4 }, { phrase: 'scaffolding', weight: 4 },
      { phrase: 'scaffold', weight: 3 }, { phrase: 'ladder', weight: 3 },
      { phrase: 'platform', weight: 1 }
    ]
  },
  FIRE_HOT_WORK: {
    label: 'Fire & Hot Work',
    priority: 3,
    keywords: [
      { phrase: 'hot work permit', weight: 5 }, { phrase: 'flashback arrestor', weight: 5 },
      { phrase: 'fire extinguisher', weight: 5 }, { phrase: 'fire blanket', weight: 5 },
      { phrase: 'fire watch', weight: 5 }, { phrase: 'gas cutting', weight: 5 },
      { phrase: 'oxygen cylinder', weight: 5 }, { phrase: 'welding machine', weight: 4 },
      { phrase: 'welding cable', weight: 4 }, { phrase: 'combustible material', weight: 4 },
      { phrase: 'fire protection', weight: 4 }, { phrase: 'fire prevention', weight: 4 },
      { phrase: 'gas cylinder', weight: 4 }, { phrase: 'gas hose', weight: 4 },
      { phrase: 'ignition source', weight: 4 }, { phrase: 'fire hazard', weight: 4 },
      { phrase: 'hot work', weight: 5 }, { phrase: 'acetylene', weight: 4 },
      { phrase: 'welding', weight: 4 }, { phrase: 'grinding', weight: 3 },
      { phrase: 'cutting', weight: 2 }, { phrase: 'torch', weight: 3 },
      { phrase: 'spark', weight: 2 }, { phrase: 'flame', weight: 2 },
      { phrase: 'extinguisher', weight: 3 }
    ]
  },
  ELECTRICAL: {
    label: 'Electrical Safety',
    priority: 4,
    keywords: [
      { phrase: 'distribution board', weight: 5 }, { phrase: 'electrical panel', weight: 5 },
      { phrase: 'circuit breaker', weight: 5 }, { phrase: 'temporary power', weight: 5 },
      { phrase: 'electrical isolation', weight: 5 }, { phrase: 'unauthorized connection', weight: 5 },
      { phrase: 'exposed wire', weight: 5 }, { phrase: 'damaged cable', weight: 5 },
      { phrase: 'electrical cable', weight: 4 }, { phrase: 'power cable', weight: 4 },
      { phrase: 'extension cable', weight: 4 }, { phrase: 'electrical connection', weight: 4 },
      { phrase: 'electric shock', weight: 5 }, { phrase: 'electrical', weight: 3 },
      { phrase: 'electricity', weight: 3 }, { phrase: 'grounding', weight: 4 },
      { phrase: 'earthing', weight: 4 }, { phrase: 'elcb', weight: 5 },
      { phrase: 'rccb', weight: 5 }, { phrase: 'breaker', weight: 2 },
      { phrase: 'socket', weight: 2 }, { phrase: 'plug', weight: 1 },
      { phrase: 'cable', weight: 1 }, { phrase: 'db', weight: 1 }
    ]
  },
  WORK_AT_HEIGHT: {
    label: 'Work at Height',
    priority: 5,
    keywords: [
      { phrase: 'work at height', weight: 5 }, { phrase: 'height work', weight: 5 },
      { phrase: 'fall protection', weight: 5 }, { phrase: 'fall arrest', weight: 5 },
      { phrase: 'retractable lifeline', weight: 5 }, { phrase: 'double lanyard', weight: 5 },
      { phrase: 'anchor point', weight: 5 }, { phrase: 'leading edge', weight: 5 },
      { phrase: 'floor opening', weight: 5 }, { phrase: 'edge protection', weight: 5 },
      { phrase: 'dropped object', weight: 4 }, { phrase: 'unsecured tools', weight: 4 },
      { phrase: 'elevated work', weight: 4 }, { phrase: 'overhead work', weight: 4 },
      { phrase: 'fall hazard', weight: 4 }, { phrase: 'roof work', weight: 4 },
      { phrase: 'open edge', weight: 4 }, { phrase: 'lifeline', weight: 4 },
      { phrase: 'anchorage', weight: 4 }, { phrase: 'lanyard', weight: 4 },
      { phrase: 'srl', weight: 3 }, { phrase: 'harness', weight: 2 }
    ]
  },
  LIFTING_RIGGING: {
    label: 'Lifting & Rigging',
    priority: 6,
    keywords: [
      { phrase: 'lifting operation', weight: 5 }, { phrase: 'lifting supervisor', weight: 5 },
      { phrase: 'suspended load', weight: 5 }, { phrase: 'lifting plan', weight: 5 },
      { phrase: 'crane inspection', weight: 5 }, { phrase: 'exclusion zone', weight: 3 },
      { phrase: 'lifting zone', weight: 4 }, { phrase: 'mobile crane', weight: 5 },
      { phrase: 'tower crane', weight: 5 }, { phrase: 'wire rope', weight: 4 },
      { phrase: 'chain sling', weight: 5 }, { phrase: 'web sling', weight: 5 },
      { phrase: 'lifting hook', weight: 4 }, { phrase: 'lifting gear', weight: 4 },
      { phrase: 'heavy lift', weight: 4 }, { phrase: 'tag line', weight: 4 },
      { phrase: 'dropped load', weight: 5 }, { phrase: 'signalman', weight: 4 },
      { phrase: 'banksman', weight: 3 }, { phrase: 'rigger', weight: 4 },
      { phrase: 'rigging', weight: 4 }, { phrase: 'shackle', weight: 4 },
      { phrase: 'sling', weight: 3 }, { phrase: 'crane', weight: 4 },
      { phrase: 'forklift', weight: 3 }, { phrase: 'lifting', weight: 2 },
      { phrase: 'swl', weight: 3 }, { phrase: 'wll', weight: 3 },
      { phrase: 'hook', weight: 1 }, { phrase: 'load', weight: 1 }
    ]
  },
  BARRICADING_ACCESS: {
    label: 'Barricading & Access',
    priority: 7,
    keywords: [
      { phrase: 'hard barricade', weight: 5 }, { phrase: 'warning tape', weight: 5 },
      { phrase: 'caution tape', weight: 5 }, { phrase: 'access control', weight: 5 },
      { phrase: 'restricted area', weight: 5 }, { phrase: 'danger zone', weight: 4 },
      { phrase: 'warning sign', weight: 4 }, { phrase: 'safety sign', weight: 4 },
      { phrase: 'pedestrian access', weight: 4 }, { phrase: 'emergency access', weight: 4 },
      { phrase: 'blocked access', weight: 4 }, { phrase: 'blocked walkway', weight: 3 },
      { phrase: 'unauthorized entry', weight: 5 }, { phrase: 'excavation barricade', weight: 5 },
      { phrase: 'excavation protection', weight: 4 }, { phrase: 'barricading', weight: 4 },
      { phrase: 'barricade', weight: 4 }, { phrase: 'exclusion zone', weight: 3 },
      { phrase: 'signage', weight: 2 }, { phrase: 'barrier', weight: 2 }
    ]
  },
  HOUSEKEEPING: {
    label: 'Housekeeping',
    priority: 8,
    keywords: [
      { phrase: 'poor housekeeping', weight: 5 }, { phrase: 'housekeeping violation', weight: 5 },
      { phrase: 'housekeeping issue', weight: 5 }, { phrase: 'material storage', weight: 3 },
      { phrase: 'improper storage', weight: 4 }, { phrase: 'poor storage', weight: 4 },
      { phrase: 'trip hazard', weight: 5 }, { phrase: 'slip hazard', weight: 5 },
      { phrase: 'scattered material', weight: 4 }, { phrase: 'slippery floor', weight: 5 },
      { phrase: 'loose material', weight: 3 }, { phrase: 'waste disposal', weight: 3 },
      { phrase: 'oil spill', weight: 3 }, { phrase: 'water spill', weight: 3 },
      { phrase: 'blocked walkway', weight: 3 }, { phrase: 'blocked passage', weight: 4 },
      { phrase: 'housekeeping', weight: 4 }, { phrase: 'debris', weight: 3 },
      { phrase: 'garbage', weight: 3 }, { phrase: 'scrap', weight: 2 },
      { phrase: 'waste', weight: 1 }, { phrase: 'obstruction', weight: 2 }
    ]
  },
  TOOLS_EQUIPMENT: {
    label: 'Tools & Equipment',
    priority: 9,
    keywords: [
      { phrase: 'grinding disc', weight: 5 }, { phrase: 'cutting disc', weight: 5 },
      { phrase: 'abrasive disc', weight: 5 }, { phrase: 'disc guard', weight: 5 },
      { phrase: 'machine guard', weight: 5 }, { phrase: 'missing guard', weight: 5 },
      { phrase: 'grinding machine', weight: 5 }, { phrase: 'cutting machine', weight: 4 },
      { phrase: 'drilling machine', weight: 4 }, { phrase: 'circular saw', weight: 5 },
      { phrase: 'defective equipment', weight: 5 }, { phrase: 'damaged equipment', weight: 5 },
      { phrase: 'damaged tool', weight: 5 }, { phrase: 'defective tool', weight: 5 },
      { phrase: 'rated rpm', weight: 5 }, { phrase: 'pneumatic tool', weight: 4 },
      { phrase: 'power tool', weight: 4 }, { phrase: 'hand tool', weight: 3 },
      { phrase: 'air tool', weight: 3 }, { phrase: 'grinder', weight: 3 },
      { phrase: 'compressor', weight: 3 }, { phrase: 'toolbox', weight: 2 },
      { phrase: 'guard', weight: 2 }, { phrase: 'drill', weight: 2 },
      { phrase: 'rpm', weight: 2 }, { phrase: 'equipment', weight: 1 },
      { phrase: 'tool', weight: 1 }, { phrase: 'tools', weight: 1 },
      { phrase: 'calibration', weight: 2 }, { phrase: 'inspection', weight: 1 }
    ]
  },
  CHEMICAL_PROCESS: {
    label: 'Chemical / Process Safety',
    priority: 10,
    keywords: [
      { phrase: 'safety data sheet', weight: 5 }, { phrase: 'chemical handling', weight: 5 },
      { phrase: 'chemical storage', weight: 5 }, { phrase: 'chemical spill', weight: 5 },
      { phrase: 'hazardous substance', weight: 5 }, { phrase: 'hazardous material', weight: 5 },
      { phrase: 'secondary containment', weight: 5 }, { phrase: 'gas detector', weight: 4 },
      { phrase: 'gas testing', weight: 4 }, { phrase: 'oxygen deficiency', weight: 5 },
      { phrase: 'flammable liquid', weight: 5 }, { phrase: 'chemical container', weight: 4 },
      { phrase: 'chemical label', weight: 4 }, { phrase: 'gas leak', weight: 5 },
      { phrase: 'oil leak', weight: 3 }, { phrase: 'msds', weight: 5 },
      { phrase: 'sds', weight: 4 }, { phrase: 'hydrocarbon', weight: 4 },
      { phrase: 'corrosive', weight: 4 }, { phrase: 'toxic', weight: 3 },
      { phrase: 'solvent', weight: 3 }, { phrase: 'caustic', weight: 4 },
      { phrase: 'chemical', weight: 3 }, { phrase: 'ventilation', weight: 2 },
      { phrase: 'h2s', weight: 4 }, { phrase: 'lel', weight: 3 },
      { phrase: 'acid', weight: 2 }, { phrase: 'diesel', weight: 2 },
      { phrase: 'fuel', weight: 1 }, { phrase: 'exposure', weight: 1 }
    ]
  },
  EXCAVATION_CIVIL: {
    label: 'Excavation & Civil',
    priority: 11,
    keywords: [
      { phrase: 'excavation permit', weight: 5 }, { phrase: 'underground service', weight: 5 },
      { phrase: 'excavation ladder', weight: 5 }, { phrase: 'spoil pile', weight: 4 },
      { phrase: 'edge protection', weight: 3 }, { phrase: 'civil work', weight: 4 },
      { phrase: 'concrete work', weight: 4 }, { phrase: 'formwork', weight: 4 },
      { phrase: 'shuttering', weight: 4 }, { phrase: 'reinforcement', weight: 3 },
      { phrase: 'breaking work', weight: 4 }, { phrase: 'trenching', weight: 5 },
      { phrase: 'excavation', weight: 4 }, { phrase: 'trench', weight: 4 },
      { phrase: 'shoring', weight: 5 }, { phrase: 'benching', weight: 4 },
      { phrase: 'cave-in', weight: 5 }, { phrase: 'demolition', weight: 3 },
      { phrase: 'rebar', weight: 3 }, { phrase: 'soil', weight: 1 }
    ]
  },
  CONFINED_SPACE: {
    label: 'Confined Space',
    priority: 12,
    keywords: [
      { phrase: 'confined space entry', weight: 5 }, { phrase: 'confined space', weight: 5 },
      { phrase: 'entry permit', weight: 3 }, { phrase: 'vessel entry', weight: 5 },
      { phrase: 'tank entry', weight: 5 }, { phrase: 'rescue plan', weight: 4 },
      { phrase: 'rescue equipment', weight: 4 }, { phrase: 'standby man', weight: 5 },
      { phrase: 'gas detector', weight: 3 }, { phrase: 'gas test', weight: 3 },
      { phrase: 'manhole', weight: 4 }, { phrase: 'chamber', weight: 2 },
      { phrase: 'attendant', weight: 2 }, { phrase: 'oxygen', weight: 1 },
      { phrase: 'lel', weight: 2 }, { phrase: 'h2s', weight: 2 }
    ]
  },
  VEHICLE_TRAFFIC: {
    label: 'Vehicle & Traffic Safety',
    priority: 13,
    keywords: [
      { phrase: 'traffic management', weight: 5 }, { phrase: 'reversing alarm', weight: 5 },
      { phrase: 'vehicle inspection', weight: 5 }, { phrase: 'driving violation', weight: 5 },
      { phrase: 'road safety', weight: 4 }, { phrase: 'mobile equipment', weight: 4 },
      { phrase: 'mobile plant', weight: 4 }, { phrase: 'seat belt', weight: 4 },
      { phrase: 'pedestrian', weight: 3 }, { phrase: 'forklift', weight: 3 },
      { phrase: 'spotter', weight: 3 }, { phrase: 'banksman', weight: 2 },
      { phrase: 'vehicle', weight: 2 }, { phrase: 'traffic', weight: 3 },
      { phrase: 'driving', weight: 2 }, { phrase: 'reversing', weight: 3 },
      { phrase: 'parking', weight: 1 }, { phrase: 'speed', weight: 1 }
    ]
  },
  PERMIT_LOTO: {
    label: 'Permit / LOTO / Safe Work Procedure',
    priority: 14,
    keywords: [
      { phrase: 'permit to work', weight: 5 }, { phrase: 'work permit', weight: 5 },
      { phrase: 'energy isolation', weight: 5 }, { phrase: 'method statement', weight: 5 },
      { phrase: 'risk assessment', weight: 4 }, { phrase: 'toolbox talk', weight: 5 },
      { phrase: 'permit violation', weight: 5 }, { phrase: 'expired permit', weight: 5 },
      { phrase: 'missing permit', weight: 5 }, { phrase: 'lockout', weight: 4 },
      { phrase: 'tagout', weight: 4 }, { phrase: 'isolation', weight: 3 },
      { phrase: 'authorization', weight: 2 }, { phrase: 'procedure', weight: 1 },
      { phrase: 'loto', weight: 5 }, { phrase: 'ptw', weight: 5 },
      { phrase: 'permit', weight: 2 }, { phrase: 'jsa', weight: 4 },
      { phrase: 'jha', weight: 4 }, { phrase: 'tbt', weight: 4 }
    ]
  },
  ENVIRONMENTAL: {
    label: 'Environmental',
    priority: 15,
    keywords: [
      { phrase: 'environmental violation', weight: 5 }, { phrase: 'hazardous waste', weight: 5 },
      { phrase: 'waste segregation', weight: 5 }, { phrase: 'soil contamination', weight: 5 },
      { phrase: 'air pollution', weight: 5 }, { phrase: 'water pollution', weight: 5 },
      { phrase: 'waste disposal', weight: 3 }, { phrase: 'oil spill', weight: 3 },
      { phrase: 'wastewater', weight: 4 }, { phrase: 'recycling', weight: 3 },
      { phrase: 'environmental', weight: 4 }, { phrase: 'pollution', weight: 4 },
      { phrase: 'emission', weight: 3 }, { phrase: 'sewage', weight: 3 },
      { phrase: 'spill', weight: 2 }, { phrase: 'dust', weight: 1 },
      { phrase: 'noise', weight: 1 }, { phrase: 'waste', weight: 1 }
    ]
  }
};

/** Deterministic priority when scores tie (lower index = higher priority) */
const OBSERVATION_CATEGORY_PRIORITY = [
  'PPE', 'FIRE_HOT_WORK', 'TOOLS_EQUIPMENT', 'ELECTRICAL', 'WORK_AT_HEIGHT',
  'LIFTING_RIGGING', 'SCAFFOLDING', 'CONFINED_SPACE', 'CHEMICAL_PROCESS',
  'EXCAVATION_CIVIL', 'BARRICADING_ACCESS', 'HOUSEKEEPING', 'VEHICLE_TRAFFIC',
  'PERMIT_LOTO', 'ENVIRONMENTAL'
];

function normalizeObservationText(text) {
  if (text === null || text === undefined) return '';
  return String(text)
    .toLowerCase()
    .replace(/[\u2018\u2019\u201c\u201d]/g, '')
    .replace(/[^a-z0-9\s\-\/&]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Controlled Root Cause taxonomy — analytics only (sheet never rewritten).
 * Chart may only show these labels.
 */
const ROOT_CAUSE_STANDARD_LABELS = [
  'Supervision',
  'Negligence / Shortcut',
  'Planning',
  'Inspection',
  'PPE Compliance',
  'Material Management',
  'Housekeeping',
  'Equipment / Tools',
  'Training / Competency',
  'Permit / Procedure',
  'Other',
  'Needs Review',
  'Unspecified'
];

/** Explicit root-cause field phrases → parent label */
const ROOT_CAUSE_FIELD_PATTERNS = [
  { label: 'Supervision', patterns: [
    'inadequate supervision', 'inadequat supervision', 'lack of proper supervision',
    'lack of supervision', 'poor supervision', 'failure of supervision',
    'lack of competent supervision', 'failure to supervise', 'no supervision',
    'supervisory failure', 'supervisor failed', 'inadequate monitoring',
    'lack of monitoring', 'poor monitoring', 'lack of proper monitor',
    'inadequate supervision and failure', 'supervision'
  ]},
  { label: 'Negligence / Shortcut', patterns: [
    'negligence and taking shortcut', 'negligence and taking short cut',
    'negligence and shortcut', 'taking shortcut', 'taking short cut',
    'shortcut practice', 'short cut practice', 'short-cut', 'shortcut',
    'short cut', 'negligence', 'carelessness', 'willful non compliance',
    'failure to follow procedure', 'failure to follow procedures',
    'failure to comply', 'non compliance', 'noncompliance'
  ]},
  { label: 'Planning', patterns: [
    'inadequate planning', 'poor job planning', 'poor planning',
    'inadequate work preparation', 'lack of proper planning', 'lack of planning',
    'inadequate preparation', 'poor preparation', 'insufficient planning',
    'lack of communication', 'poor communication', 'inadequate coordination',
    'poor planning and lack of communication', 'lack of proper planning and supervision',
    'planning'
  ]},
  { label: 'Inspection', patterns: [
    'inadequate inspection', 'failure to verify inspection', 'poor inspection',
    'failure to inspect', 'lack of inspection', 'inspection failure',
    'expired inspection', 'inspection and certification', 'pre use inspection',
    'pre-use inspection', 'failure to verify', 'inspection'
  ]},
  { label: 'PPE Compliance', patterns: [
    'failure to comply with ppe', 'ppe requirements', 'ppe compliance',
    'lack of ppe', 'not wearing ppe', 'ppe non compliance', 'mandatory ppe',
    'personal protective', 'ppe compliance', 'ppe'
  ]},
  { label: 'Material Management', patterns: [
    'material management', 'material storage', 'material handling',
    'improper storage', 'poor material', 'inadequate material',
    'material shifting', 'storage of material', 'manual handling'
  ]},
  { label: 'Housekeeping', patterns: [
    'poor housekeeping', 'inadequate housekeeping', 'housekeeping practices',
    'lack of housekeeping', 'housekeeping'
  ]},
  { label: 'Equipment / Tools', patterns: [
    'equipment failure', 'equipment malfunction', 'tool failure',
    'defective equipment', 'defective tool', 'improper tool',
    'unauthorized tool', 'equipment safety', 'tools and equipment',
    'equipment'
  ]},
  { label: 'Training / Competency', patterns: [
    'lack of training', 'inadequate training', 'incompetent',
    'unauthorized person', 'not competent', 'lack of awareness',
    'lack of competency', 'training', 'competency'
  ]},
  { label: 'Permit / Procedure', patterns: [
    'permit to work', 'incomplete permit', 'ptw compliance',
    'permit preparation', 'procedure not followed', 'jsa',
    'method statement', 'work permit', 'ptw'
  ]}
];

/**
 * Observation-text evidence patterns (Main Safety Observation language).
 * Used ONLY when Root-Causes is blank/generic. Deterministic phrase evidence —
 * does NOT map category names alone to a root cause.
 */
const ROOT_CAUSE_OBS_EVIDENCE = [
  { label: 'PPE Compliance', patterns: [
    'without wearing', 'not wearing', 'without a face shield', 'without face shield',
    'without safety glasses', 'without gloves', 'without helmet', 'without harness',
    'without ear', 'chin strap', 'face shield', 'safety glasses', 'safety goggles',
    'not using ppe', 'ppe not', 'no ppe', 'ear plugs', 'hearing protection',
    'reflective vest', 'red jacket', 'safety shoes', 'without insulated gloves'
  ]},
  { label: 'Supervision', patterns: [
    'fire watcher was found away', 'fire watcher was observed', 'fire watcher away',
    'away from the hot work', 'away from the designated', 'without an equipment attendant',
    'equipment attendant was busy', 'attendant was busy', 'no supervisor',
    'supervisor was not', 'lack of supervision at', 'unattended'
  ]},
  { label: 'Housekeeping', patterns: [
    'poor housekeeping', 'scattered', 'debris', 'obstructed', 'obstruction',
    'trip hazard', 'walkway', 'access blocked', 'pathway was blocked',
    'materials were scattered', 'loose materials', 'waste was found',
    'plastic waste', 'housekeeping'
  ]},
  { label: 'Inspection', patterns: [
    'inspection tag', 'tpi tag', 'tpi certification', 'third-party inspection',
    'third party inspection', 'expired', 'without a valid', 'not updated',
    'white inspection tag', 'red inspection tag', 'without valid tpi',
    'inspection status', 'certification were not available', 'no inspection'
  ]},
  { label: 'Equipment / Tools', patterns: [
    'damaged cable', 'damaged insulation', 'insulation was found damaged',
    'defective', 'malfunction', 'side handle removed', 'without wheel stopper',
    'improper grounding', 'rusted steel bar', 'damaged fire blanket',
    'torn and damaged', 'without the protective metal cap', 'rebar piece instead',
    'unauthorized or improvised tools', 'tool failure'
  ]},
  { label: 'Permit / Procedure', patterns: [
    'not included in the work permit', 'not mention on permit', 'not mentioned on permit',
    'incomplete permit', 'permit audit', 'not clearly mentioned in the jsa',
    'jsa available', 'cross-marked on the permit', 'ptw', 'work permit under'
  ]},
  { label: 'Material Management', patterns: [
    'manually lifting', 'manual lifting', 'manual handling', 'without assistance',
    'material storage', 'stored near', 'stored without', 'stored on a scaffolding',
    'improper storage', 'material shifting pathway'
  ]},
  { label: 'Negligence / Shortcut', patterns: [
    'taking shortcut', 'short cut', 'shortcut', 'negligence',
    'was observed climbing', 'carrying tools in both hands',
    'without a tag line', 'without tool lanyard', 'manually holding the ladder',
    'passing through a restricted', 'entering the vicinity of a suspended'
  ]},
  { label: 'Planning', patterns: [
    'poor illumination', 'inadequate illumination', 'inadequate lighting',
    'without proper barricad', 'improper barricad', 'barricading was observed',
    'simultaneous operations', 'simops', 'lack of proper planning',
    'inadequate planning', 'work sequence', 'coordination'
  ]},
  { label: 'Training / Competency', patterns: [
    'incompetent', 'unauthorized person', 'not using a tag line',
    'lack of awareness', 'not competent', 'unauthorized'
  ]}
];

function isGenericRootCauseValue_(raw) {
  const s = String(raw || '').trim();
  if (!s) return true;
  return /^(unspecified|n\/?a|na|nil|none|null|undefined|unknown|not specified|not applicable|-|\.|--|n\.a\.?|other)$/i.test(s);
}

function matchRootPatterns_(text, groups) {
  if (!text) return null;
  let best = null;
  let bestLen = 0;
  for (let i = 0; i < groups.length; i++) {
    const g = groups[i];
    const pats = g.patterns || [];
    for (let j = 0; j < pats.length; j++) {
      const p = normalizeObservationText(pats[j]);
      if (!p || p.length < 3) continue;
      if (text.indexOf(p) !== -1 && p.length > bestLen) {
        best = g.label;
        bestLen = p.length;
      }
    }
  }
  return best;
}

/**
 * Full evidence-based root-cause classification (analytics only).
 * Priority: Root field → Main Observation text → supporting fields (type/category as weak signals only).
 * @returns {{ label: string, source: string }}
 */
function classifyRootCauseEvidence(rootRaw, mainText, typeText, categoryText) {
  const root = normalizeObservationText(rootRaw);
  const main = normalizeObservationText(mainText);
  const type = normalizeObservationText(typeText);
  const cat = normalizeObservationText(categoryText);
  const generic = isGenericRootCauseValue_(rootRaw);

  // 1) Meaningful root-cause field
  if (!generic && root) {
    const fromRoot = matchRootPatterns_(root, ROOT_CAUSE_FIELD_PATTERNS);
    if (fromRoot) return { label: fromRoot, source: 'root' };
    // Clear free-text root that does not map → Other
    if (root.length >= 3) return { label: 'Other', source: 'other' };
  }

  // 2) Main observation text (strong evidence)
  if (main && main.length >= 12) {
    const fromMain = matchRootPatterns_(main, ROOT_CAUSE_OBS_EVIDENCE);
    if (fromMain) return { label: fromMain, source: 'observation' };
    // Also allow explicit root-cause language inside the narrative
    const fromMainRootLang = matchRootPatterns_(main, ROOT_CAUSE_FIELD_PATTERNS);
    if (fromMainRootLang) return { label: fromMainRootLang, source: 'observation' };
  }

  // 3) Supporting signals only when combined with some observation substance —
  // NEVER map Category alone (e.g. Work at Height ≠ Supervision)
  const support = (type + ' ' + cat).trim();
  if (main && main.length >= 12 && support) {
    // Weak: type/category phrases that are themselves root-like
    const fromSupport = matchRootPatterns_(support, ROOT_CAUSE_FIELD_PATTERNS);
    if (fromSupport) return { label: fromSupport, source: 'supporting' };
  }

  // 4) Has narrative but no reliable causal evidence → Needs Review
  if (main && main.length >= 20) {
    return { label: 'Needs Review', source: 'needs_review' };
  }

  // 5) Truly empty / unusable
  return { label: 'Unspecified', source: 'unspecified' };
}

/** Backward-compatible string API used by aggregation */
function normalizeRootCauseStandard(rootRaw, contextText) {
  // contextText may be "main | type | category" joined by caller
  const parts = String(contextText || '').split(/\s*\|\s*/);
  let main = contextText;
  let type = '';
  let cat = '';
  if (parts.length >= 3) {
    main = parts[0];
    type = parts[1];
    cat = parts[2];
  }
  return classifyRootCauseEvidence(rootRaw, main, type, cat).label;
}

/**
 * Diagnostic — full sheet evaluation + source breakdown. No sheet writes.
 */
function diagnoseRootCauseNormalization() {
  const samples = [
    { root: 'Inadequate supervision', main: '' },
    { root: 'Lack of Proper Supervision', main: '' },
    { root: 'Negligence and taking short cut', main: '' },
    { root: '', main: 'Worker was observed grinding without wearing a face shield.' },
    { root: '', main: 'Fire watcher was found away from the hot work location during welding activity.' },
    { root: '', main: 'Loose grinding discs and tools were scattered on the scaffolding platform.' },
    { root: '', main: 'Portable lights were found in use without a valid Third-Party Inspection (TPI) tag.' },
    { root: '', main: 'Category only test', type: 'Unsafe Act', category: 'Work at Height' },
    { root: '', main: '' }
  ];
  const sampleResults = samples.map(function (s) {
    const r = classifyRootCauseEvidence(s.root, s.main, s.type || '', s.category || '');
    return { input: s, result: r };
  });

  const totals = {
    totalRows: 0,
    rootPopulated: 0,
    fromRoot: 0,
    fromObservation: 0,
    fromSupporting: 0,
    other: 0,
    needsReview: 0,
    unspecified: 0
  };
  const byLabel = {};

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const soSheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (soSheet && soSheet.getLastRow() > 1) {
      const soData = getSheetValues(soSheet, Math.max(CONFIG.SO.COLS, 16));
      const soMap = resolveSoColumnMap(soData[0] || []);
      const rootIdx = soMap.root >= 0 ? soMap.root : CONFIG.SO.ROOT;
      const mainIdx = soMap.main >= 0 ? soMap.main : CONFIG.SO.MAIN;
      const typeIdx = soMap.type >= 0 ? soMap.type : CONFIG.SO.TYPE;
      const catIdx = soMap.category >= 0 ? soMap.category : CONFIG.SO.CATEGORY;
      for (let i = 1; i < soData.length; i++) {
        const row = soData[i];
        totals.totalRows++;
        const rootRaw = String(row[rootIdx] || '').trim();
        if (rootRaw && !isGenericRootCauseValue_(rootRaw)) totals.rootPopulated++;
        const r = classifyRootCauseEvidence(
          rootRaw,
          String(row[mainIdx] || ''),
          String(row[typeIdx] || ''),
          String(row[catIdx] || '')
        );
        byLabel[r.label] = (byLabel[r.label] || 0) + 1;
        if (r.source === 'root') totals.fromRoot++;
        else if (r.source === 'observation') totals.fromObservation++;
        else if (r.source === 'supporting') totals.fromSupporting++;
        else if (r.source === 'other') totals.other++;
        else if (r.source === 'needs_review') totals.needsReview++;
        else totals.unspecified++;
      }
    }
  } catch (e) {
    totals.error = String(e);
  }

  const pct = function (n) {
    return totals.totalRows ? Math.round((n / totals.totalRows) * 1000) / 10 : 0;
  };
  const illegal = Object.keys(byLabel).filter(function (k) {
    return ROOT_CAUSE_STANDARD_LABELS.indexOf(k) === -1;
  });

  const out = {
    sampleResults: sampleResults,
    totals: totals,
    percentages: {
      rootPopulated: pct(totals.rootPopulated),
      classifiedFromRoot: pct(totals.fromRoot),
      inferredFromObservation: pct(totals.fromObservation),
      fromSupporting: pct(totals.fromSupporting),
      other: pct(totals.other),
      needsReview: pct(totals.needsReview),
      unspecified: pct(totals.unspecified),
      classified: pct(totals.fromRoot + totals.fromObservation + totals.fromSupporting + totals.other)
    },
    byRootCause: byLabel,
    illegalKeys: illegal,
    pass: illegal.length === 0
  };
  Logger.log(JSON.stringify(out, null, 2));
  return out;
}

function escapeRegExpObs(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Word-boundary-aware match. Phrases matched as normalized substrings;
 * single tokens require word boundaries to avoid partial-word hits.
 */
function observationTextMatchesKeyword(normText, keyword) {
  const k = normalizeObservationText(keyword);
  if (!k || !normText) return false;
  if (k.indexOf(' ') !== -1) {
    return normText.indexOf(k) !== -1;
  }
  try {
    const re = new RegExp('(?:^|\\s)' + escapeRegExpObs(k) + '(?=\\s|$)');
    return re.test(normText);
  } catch (e) {
    return normText.indexOf(k) !== -1;
  }
}

/**
 * Classify observation text → matched categories + primary (highest weighted score).
 * Same category never appears twice. Never throws to callers when used via try/catch.
 */
function classifyObservation(text) {
  const norm = normalizeObservationText(text);
  const empty = {
    primaryCategory: null,
    primaryLabel: 'Unclassified',
    secondaryCategories: [],
    matchedCategories: [],
    scores: {},
    matches: {},
    totalScore: 0
  };
  if (!norm) return empty;

  const scores = {};
  const matches = {};

  Object.keys(OBSERVATION_CATEGORIES).forEach(function (catId) {
    const cfg = OBSERVATION_CATEGORIES[catId];
    // Prefer longer phrases first
    const kws = (cfg.keywords || []).slice().sort(function (a, b) {
      return String(b.phrase || '').length - String(a.phrase || '').length;
    });
    let score = 0;
    const hitPhrases = [];
    kws.forEach(function (kw) {
      const phrase = kw.phrase || kw;
      const weight = typeof kw.weight === 'number' ? kw.weight : 1;
      if (observationTextMatchesKeyword(norm, phrase)) {
        score += weight;
        hitPhrases.push(String(phrase));
      }
    });
    if (score > 0) {
      scores[catId] = score;
      matches[catId] = hitPhrases;
    }
  });

  const matchedCategories = Object.keys(scores);
  if (!matchedCategories.length) return empty;

  // Primary = highest score; tie → OBSERVATION_CATEGORY_PRIORITY order
  matchedCategories.sort(function (a, b) {
    const ds = (scores[b] || 0) - (scores[a] || 0);
    if (ds !== 0) return ds;
    return OBSERVATION_CATEGORY_PRIORITY.indexOf(a) - OBSERVATION_CATEGORY_PRIORITY.indexOf(b);
  });

  const primaryCategory = matchedCategories[0];
  const primaryLabel = (OBSERVATION_CATEGORIES[primaryCategory] && OBSERVATION_CATEGORIES[primaryCategory].label) || primaryCategory;
  const secondaryCategories = matchedCategories.slice(1);
  let totalScore = 0;
  matchedCategories.forEach(function (id) { totalScore += scores[id] || 0; });

  return {
    primaryCategory: primaryCategory,
    primaryLabel: primaryLabel,
    secondaryCategories: secondaryCategories,
    matchedCategories: matchedCategories,
    scores: scores,
    matches: matches,
    totalScore: totalScore
  };
}

/**
 * Debug helper — returns classification detail for a sample observation text.
 * Does not write to sheets.
 */
function testClassifyObservation(sampleText) {
  const result = classifyObservation(sampleText || '');
  return createResponse(true, 'Classification result', {
    observationText: sampleText || '',
    classification: result
  });
}

/**
 * Run built-in classification self-tests (Logger + return summary).
 */
function runObservationClassificationTests() {
  const cases = [
    { text: 'Worker not wearing helmet and safety gloves.', expect: ['PPE'] },
    { text: 'Grinding activity carried out without face shield and grinder guard.', expect: ['PPE', 'TOOLS_EQUIPMENT', 'FIRE_HOT_WORK'] },
    { text: 'Scaffold missing toe board and inspection tag.', expect: ['SCAFFOLDING'] },
    { text: 'Damaged electrical cable found near work area.', expect: ['ELECTRICAL'] },
    { text: 'Worker standing under suspended load.', expect: ['LIFTING_RIGGING'] },
    { text: 'Poor housekeeping with scrap material blocking walkway.', expect: ['HOUSEKEEPING'] },
    { text: 'Confined space entry without gas testing.', expect: ['CONFINED_SPACE'] },
    { text: 'Worker was wearing helmet, gloves, goggles and safety shoes.', expect: ['PPE'] },
    { text: 'Routine walkaround with no issues noted.', expect: [] }
  ];
  const results = cases.map(function (c) {
    const cls = classifyObservation(c.text);
    const got = cls.matchedCategories || [];
    const ok = c.expect.every(function (e) { return got.indexOf(e) !== -1; }) &&
      (c.expect.length === 0 ? got.length === 0 : true);
    return { text: c.text, expected: c.expect, got: got, primary: cls.primaryCategory, pass: ok };
  });
  const passed = results.filter(function (r) { return r.pass; }).length;
  Logger.log('Classification tests: ' + passed + '/' + results.length + ' passed');
  return createResponse(true, 'Tests ' + passed + '/' + results.length + ' passed', { results: results });
}

/**
 * Dashboard/reporting: category stats from unique observations (not keyword hits).
 * Optional filters: { period, startDate, endDate, sessionToken }
 */
function getObservationCategoryStats(filters) {
  filters = filters || {};
  const auth = requireAuth(filters.sessionToken || filters, 'view');
  if (!auth.ok) return auth.response;

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet || sheet.getLastRow() < 2) {
      return createResponse(true, 'No observations', {
        totalObservations: 0,
        categories: {},
        percentages: {},
        topCategory: null,
        leastCategory: null,
        unclassified: 0
      });
    }

    const data = sheet.getDataRange().getValues();
    const soMap = resolveSoColumnMap(data[0] || []);
    const mainIdx = soMap.main >= 0 ? soMap.main : CONFIG.SO.MAIN;
    const dateIdx = soMap.date >= 0 ? soMap.date : CONFIG.SO.DATE;
    const statusIdx = soMap.status >= 0 ? soMap.status : CONFIG.SO.STATUS;

    let range = { start: null, end: null };
    if (filters.startDate || filters.endDate) {
      range.start = filters.startDate ? formatDateValue(filters.startDate) : null;
      range.end = filters.endDate ? formatDateValue(filters.endDate) : null;
    } else if (filters.period && filters.period !== 'total') {
      // reuse dashboard period helper if available via getDashboardStats path
      try {
        const today = new Date();
        const p = String(filters.period);
        if (p === 'today') {
          range.start = range.end = Utilities.formatDate(today, Session.getScriptTimeZone(), 'yyyy-MM-dd');
        }
      } catch (e) {}
    }

    const categories = {};
    let totalObservations = 0;
    let unclassified = 0;
    const seenIds = {}; // safety against duplicate rows

    for (let i = 1; i < data.length; i++) {
      const row = data[i];
      const status = String(row[statusIdx] || '');
      if (String(status).toLowerCase() === 'archived') continue;

      const idKey = String(row[soMap.id >= 0 ? soMap.id : 0] || '') + '|' + i;
      if (seenIds[idKey]) continue;
      seenIds[idKey] = true;

      const dateStr = formatDateValue(row[dateIdx]);
      if (range.start || range.end) {
        if (!isDateInRange(dateStr, range.start, range.end)) continue;
      }

      totalObservations++;
      const mainText = String(row[mainIdx] || '');
      const cls = classifyObservation(mainText);
      if (!cls.matchedCategories || !cls.matchedCategories.length) {
        unclassified++;
        categories['Unclassified'] = (categories['Unclassified'] || 0) + 1;
      } else {
        // Each matched category +1 once per observation
        cls.matchedCategories.forEach(function (catId) {
          const label = (OBSERVATION_CATEGORIES[catId] && OBSERVATION_CATEGORIES[catId].label) || catId;
          categories[label] = (categories[label] || 0) + 1;
        });
      }
    }

    const percentages = {};
    Object.keys(categories).forEach(function (k) {
      percentages[k] = totalObservations > 0
        ? Math.round((categories[k] / totalObservations) * 1000) / 10
        : 0;
    });

    let topCategory = null;
    let leastCategory = null;
    let topN = -1;
    let leastN = Infinity;
    Object.keys(categories).forEach(function (k) {
      if (k === 'Unclassified') return;
      if (categories[k] > topN) { topN = categories[k]; topCategory = k; }
      if (categories[k] < leastN) { leastN = categories[k]; leastCategory = k; }
    });

    return createResponse(true, 'Category statistics', {
      totalObservations: totalObservations,
      categories: categories,
      percentages: percentages,
      topCategory: topCategory,
      leastCategory: leastCategory,
      unclassified: unclassified
    });
  } catch (err) {
    Logger.log('getObservationCategoryStats: ' + err);
    return createResponse(false, 'Failed to compute category stats: ' + err.message);
  }
}

/**
 * Rebuild/analyze historical rows: classify each MAIN text.
 * Does NOT change Category column by default (safe).
 * Pass { writePrimary: true } to fill blank Category cells only.
 * Idempotent: never double-counts; analysis is derived from text each run.
 */
function rebuildObservationCategoryStats(options) {
  options = options || {};
  const auth = requireAuth(options.sessionToken || options, 'edit');
  if (!auth.ok) return auth.response;

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy. Try rebuild again shortly.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet || sheet.getLastRow() < 2) {
      return createResponse(true, 'No rows to analyze', { analyzed: 0 });
    }

    const data = sheet.getDataRange().getValues();
    const soMap = resolveSoColumnMap(data[0] || []);
    const mainIdx = soMap.main >= 0 ? soMap.main : CONFIG.SO.MAIN;
    const catIdx = soMap.category >= 0 ? soMap.category : CONFIG.SO.CATEGORY;
    const writePrimary = !!options.writePrimary;

    let analyzed = 0;
    let updated = 0;
    const sample = [];

    for (let i = 1; i < data.length; i++) {
      const row = data[i];
      const mainText = String(row[mainIdx] || '');
      const cls = classifyObservation(mainText);
      analyzed++;

      if (writePrimary && cls.primaryLabel && cls.primaryLabel !== 'Unclassified') {
        const existing = String(row[catIdx] || '').trim();
        if (!existing) {
          sheet.getRange(i + 1, catIdx + 1).setValue(cls.primaryLabel);
          updated++;
        }
      }

      if (sample.length < 15) {
        sample.push({
          row: i + 1,
          id: row[soMap.id >= 0 ? soMap.id : 0],
          primaryCategory: cls.primaryCategory,
          matchedCategories: cls.matchedCategories,
          matches: cls.matches
        });
      }
    }

    logAuditAction('REBUILD', 'Safety Observation', 'category-stats', '', '',
      'Rebuilt observation category analysis; analyzed=' + analyzed + ' updatedBlankCategory=' + updated);

    return createResponse(true, 'Historical classification complete', {
      analyzed: analyzed,
      blankCategoriesFilled: updated,
      sample: sample
    });
  } catch (err) {
    Logger.log('rebuildObservationCategoryStats: ' + err);
    return createResponse(false, 'Rebuild failed: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Alias for classifyObservation — name requested in requirements.
 */
function analyzeObservationCategory(text) {
  return classifyObservation(text);
}

// ==============================================================================
// DATABASE EXPORT (CSV via client download)
// ==============================================================================

/**
 * Exports sheet data as CSV (base64) — no UrlFetchApp / external_request scope required.
 * Excel and Google Sheets open these files cleanly.
 * @param {string} which - 'permits' | 'observations' | 'both'
 */
function exportSheetData(which, sessionToken) {
  if (which && typeof which === 'object') {
    sessionToken = which.sessionToken;
    which = which.which || which.mode || 'both';
  }
  const auth = requireAuth(sessionToken, 'admin');
  if (!auth.ok) return auth.response;
  try {
    const mode = String(which || 'both').toLowerCase().trim();
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const stamp = Utilities.formatDate(new Date(), Session.getScriptTimeZone() || 'GMT', 'yyyy-MM-dd');

    const wantPermits = (mode === 'permits' || mode === 'both' || mode === 'permit' || mode === 'wp');
    const wantObs = (mode === 'observations' || mode === 'both' || mode === 'observation' || mode === 'so');

    if (!wantPermits && !wantObs) {
      return createResponse(false, 'Unknown export option. Use permits, observations, or both.');
    }

    function sheetToCsvBase64(sheetName) {
      const sheet = ss.getSheetByName(sheetName);
      if (!sheet || sheet.getLastRow() < 1) {
        return Utilities.base64Encode(Utilities.newBlob(sheetName + '\n').getBytes());
      }
      const values = sheet.getDataRange().getValues();
      const lines = [];
      for (let r = 0; r < values.length; r++) {
        const cols = values[r].map(function (cell) {
          if (cell instanceof Date) {
            try { return formatTimestamp(cell); } catch (e) { return String(cell); }
          }
          let s = String(cell == null ? '' : cell).replace(/^'/, '');
          if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
          return s;
        });
        // skip fully empty data rows (keep header)
        if (r > 0 && cols.every(function (c) { return String(c).trim() === ''; })) continue;
        lines.push(cols.join(','));
      }
      const csv = lines.join('\r\n');
      // UTF-8 BOM helps Excel open UTF-8 correctly
      const blob = Utilities.newBlob('\uFEFF' + csv, 'text/csv', sheetName + '.csv');
      return Utilities.base64Encode(blob.getBytes());
    }

    const files = [];
    if (wantPermits) {
      files.push({
        filename: 'Work_Permit_Records_' + stamp + '.csv',
        base64: sheetToCsvBase64(CONFIG.SHEETS.WORK_PERMITS),
        mime: 'text/csv;charset=utf-8'
      });
    }
    if (wantObs) {
      files.push({
        filename: 'Safety_Observations_' + stamp + '.csv',
        base64: sheetToCsvBase64(CONFIG.SHEETS.SAFETY_OBSERVATIONS),
        mime: 'text/csv;charset=utf-8'
      });
    }

    if (!files.length) {
      return createResponse(false, 'No sheets available to export.');
    }

    logAuditAction('EXPORT', 'Database', mode, '', '', 'Sheet data exported as CSV: ' + mode);
    return createResponse(true, 'Export data ready', { files: files });
  } catch (err) {
    Logger.log('exportSheetData: ' + err.toString());
    return createResponse(false, 'Failed to export sheet data: ' + err.message);
  }
}

// ==============================================================================
// AUDIT LOG & SETTINGS SERVICES
// ==============================================================================

/**
 * Appends an entry to the Audit Log sheet
 */
function logAuditAction(action, moduleName, recordId, targetRef, prevValue, newValue) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.AUDIT_LOG);
    if (!sheet) return;

    const userContext = getUserContext();
    const timestampStr = formatTimestamp(new Date());

    sheet.appendRow([
      timestampStr,
      userContext.email,
      action,
      moduleName,
      recordId,
      targetRef || '',
      prevValue || '',
      newValue || '',
      `System Log`
    ]);
  } catch (err) {
    Logger.log('Audit Log error: ' + err.toString());
  }
}

/**
 * Fetches recent audit logs
 */
function getAuditLogs(limit, sessionToken) {
  if (limit && typeof limit === 'object') {
    sessionToken = limit.sessionToken;
    limit = limit.limit;
  }
  const auth = requireAuth(sessionToken, 'admin');
  if (!auth.ok) return auth.response;
  try {
    limit = limit || 50;
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.AUDIT_LOG);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(true, 'No audit logs', []);

    const raw = sheet.getDataRange().getValues();
    const logs = [];
    const max = Math.min(raw.length - 1, limit);

    for (let i = raw.length - 1; i >= raw.length - max; i--) {
      const r = raw[i];
      logs.push({
        timestamp: formatTimestamp(r[0]),
        user: String(r[1]),
        action: String(r[2]),
        module: String(r[3]),
        recordId: String(r[4]),
        targetRef: String(r[5]),
        prevValue: String(r[6]),
        newValue: String(r[7])
      });
    }

    return createResponse(true, 'Audit logs retrieved', logs);
  } catch (err) {
    return createResponse(false, 'Failed to fetch audit logs: ' + err.message);
  }
}

/**
 * Reads setting value from Settings sheet
 */
function getSettingValue(keyName) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SETTINGS);
    if (!sheet) return '';
    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).toUpperCase() === keyName.toUpperCase()) {
        return String(data[i][1]).trim();
      }
    }
  } catch (err) {
    Logger.log('Error reading setting: ' + err.toString());
  }
  return '';
}

// ==============================================================================
// USER AUTHENTICATION & MANAGEMENT
// ==============================================================================

/**
 * Verifies user credentials against the Users sheet (4-col: Username|Password|Role|Status).
 */

/**
 * Allows the signed-in user to change their own password.
 * Always requires the current (old) password — including master "admin".
 * Only the signed-in account can change that account's password here.
 */
function changeOwnPassword(payload) {
  payload = payload || {};
  const auth = requireAuth(payload.sessionToken, 'view');
  if (!auth.ok) return auth.response;
  const currentPassword = String(payload.currentPassword || '').trim();
  const newPassword = String(payload.newPassword || '').trim();
  if (!currentPassword || !newPassword) {
    return createResponse(false, 'Current password is required to set a new password.');
  }
  if (newPassword.length < 8) {
    return createResponse(false, 'New password must be at least 8 characters.');
  }
  if (currentPassword === newPassword) {
    return createResponse(false, 'New password must be different from the current password.');
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) return createResponse(false, 'System busy. Try again.');
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return createResponse(false, 'Users sheet not found.');
    const data = sheet.getDataRange().getValues();
    const uname = String(auth.user.username || '').trim().toLowerCase();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0] || '').trim().toLowerCase() === uname) {
        const stored = String(data[i][1] || '').trim().replace(/^'/, '');
        if (!verifyPassword(currentPassword, stored)) {
          return createResponse(false, 'Current password is incorrect.');
        }
        sheet.getRange(i + 1, 2).setValue(hashPassword(newPassword)).setNumberFormat('@');
        logAuditAction('CHANGE_PASSWORD', 'Auth', uname, uname, '', 'User changed own password (verified current password)');
        return createResponse(true, 'Password updated successfully.');
      }
    }
    return createResponse(false, 'User account not found.');
  } catch (err) {
    return createResponse(false, 'Failed to change password: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

function logoutUser(sessionToken) {
  destroySession(sessionToken);
  logAuditAction('LOGOUT', 'Auth', '', '', '', 'User signed out');
  return createResponse(true, 'Logged out');
}

function verifySession(sessionToken) {
  const auth = requireAuth(sessionToken, 'view');
  if (!auth.ok) return auth.response;
  return createResponse(true, 'Session valid', auth.user);
}

function verifyUserLogin(username, password) {
  try {
    const cleanUser = String(username || '').trim().toLowerCase();
    const cleanPass = String(password || '').trim().replace(/^'/, '');
    if (!cleanUser || !cleanPass) {
      return createResponse(false, 'Please enter both username and password.');
    }

    const rate = checkLoginRateLimit(cleanUser);
    if (!rate.ok) return createResponse(false, rate.message, null, 'RATE_LIMIT');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) {
      setupSpreadsheet();
      sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    }
    ensureUsersSheetStructure(ss);
    seedDefaultUsers(ss);
    SpreadsheetApp.flush();
    sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);

    if (!sheet || sheet.getLastRow() <= 1) {
      return createResponse(false, 'No users configured. Run resetMasterAdminPassword() from the Apps Script editor, then change the password after login.');
    }

    const data = sheet.getDataRange().getValues();

    const blockedStatuses = ['inactive', 'disabled', 'suspended', 'deleted', 'locked', 'false', '0', 'no'];

    for (let i = 1; i < data.length; i++) {
      const rowUser = String(data[i][0] || '').trim().toLowerCase();
      const rowPass = String(data[i][1] || '').trim().replace(/^'/, '');
      const rowRole = String(data[i][2] || 'Viewer').trim();
      const rowStatus = String(data[i][3] || '').trim().toLowerCase();

      if (rowUser === cleanUser && verifyPassword(cleanPass, rowPass)) {
        if (rowStatus && blockedStatuses.indexOf(rowStatus) !== -1) {
          return createResponse(false, 'This account is inactive. Contact your administrator.');
        }
        // Transparent migration: upgrade legacy plaintext → salted hash
        upgradePasswordHashIfNeeded(sheet, i + 1, cleanPass, rowPass);
        clearLoginRateLimit(cleanUser);
        const perms = roleToPermissions(rowRole);
        logAuditAction('LOGIN', 'Auth', String(data[i][0]), '', '', `User '${data[i][0]}' signed in`);
        const payload = {
          username:   String(data[i][0]).trim(),
          fullName:   String(data[i][0]).trim(),
          role:       perms.roleLabel,
          roleView:   perms.roleView,
          roleEdit:   perms.roleEdit,
          roleUpload: perms.roleUpload,
          department: ''
        };
        payload.sessionToken = createSession(payload);
        payload.expiresIn = CONFIG.SESSION_TTL_SECONDS;
        return createResponse(true, 'Login successful', payload);
      }
    }
    return createResponse(false, 'Invalid username or password. Please try again.');
  } catch (err) {
    Logger.log('Login error: ' + err.toString());
    return createResponse(false, 'Authentication error: ' + err.message);
  }
}

/**
 * Returns list of users WITHOUT passwords (safe for table display).
 * Super Admin session required.
 */
function getUsers(sessionTokenOrPayload) {
  try {
    const token = sessionTokenOrPayload && typeof sessionTokenOrPayload === 'object'
      ? sessionTokenOrPayload.sessionToken
      : sessionTokenOrPayload;
    const auth = requireAuth(token, 'admin');
    if (!auth.ok) return auth.response;

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    ensureUsersSheetStructure(ss);
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(true, 'No users found', []);
    const data = sheet.getDataRange().getValues();
    const users = [];
    for (let i = 1; i < data.length; i++) {
      if (!data[i][0]) continue;
      const roleRaw = String(data[i][2] || 'Viewer').trim();
      const perms = roleToPermissions(roleRaw);
      users.push({
        rowIndex:   i + 1,
        username:   String(data[i][0]).trim(),
        role:       perms.roleLabel,
        roleView:   perms.roleView,
        roleEdit:   perms.roleEdit,
        roleUpload: perms.roleUpload,
        status:     String(data[i][3] || 'Active').trim()
      });
    }
    return createResponse(true, 'Users fetched', users);
  } catch (err) {
    return createResponse(false, 'Failed to fetch users: ' + err.message);
  }
}

/**
 * Returns a single user for admin view/edit — requires Super Admin password.
 * Password field is never returned as the raw hash; only a masked indicator.
 * For edits, admin sets a new plaintext password which is re-hashed on save.
 */
function getUserSecure(username, adminPassword) {
  try {
    if (!confirmAdminPassword(adminPassword)) {
      return createResponse(false, 'Invalid admin password. Access denied.');
    }
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return createResponse(false, 'Users sheet not found.');
    const data = sheet.getDataRange().getValues();
    const target = String(username || '').trim().toLowerCase();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0] || '').trim().toLowerCase() === target) {
        const perms = roleToPermissions(data[i][2]);
        const stored = String(data[i][1] || '').trim().replace(/^'/, '');
        logAuditAction('VIEW_USER', 'Users', String(data[i][0]), '', '', 'User record viewed after admin confirmation');
        return createResponse(true, 'User loaded', {
          username: String(data[i][0]).trim(),
          // Never expose hash; show placeholder so UI knows a password exists
          password: '',
          passwordSet: !!stored,
          passwordHashed: isPasswordHashed(stored),
          role:     perms.roleLabel,
          status:   String(data[i][3] || 'Active').trim()
        });
      }
    }
    return createResponse(false, 'User not found.');
  } catch (err) {
    return createResponse(false, 'Failed to load user: ' + err.message);
  }
}

/**
 * Creates a new portal user. Layout: Username | Password | Role | Status
 * Requires signed-in Super Admin session OR master admin password.
 */
function createUser(userData) {
  userData = userData || {};
  const auth = requireAuth(userData.sessionToken, 'admin');
  const masterOk = confirmMasterAdminPassword(userData.adminPassword);
  if (!auth.ok && !masterOk) {
    return auth.ok === false && auth.response
      ? auth.response
      : createResponse(false, 'Super Admin session or master admin password required.', null, 'FORBIDDEN');
  }
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) return createResponse(false, 'System busy. Try again.');
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    ensureUsersSheetStructure(ss);
    let sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return createResponse(false, 'Users sheet not found.');

    const username = sanitizeInput(userData.username);
    const password = String(userData.password || '').trim();
    let role = String(userData.role || 'Viewer').trim();
    const status = String(userData.status || 'Active').trim() || 'Active';

    // Normalize role label
    role = roleToPermissions(role).roleLabel;

    if (!username || !password) {
      return createResponse(false, 'Username and Password are required.');
    }
    if (username.toLowerCase() === 'admin') {
      return createResponse(false, 'Username "admin" is reserved.');
    }

    if (sheet.getLastRow() > 1) {
      const existing = sheet.getRange(2, 1, sheet.getLastRow(), 1).getValues();
      for (let i = 0; i < existing.length; i++) {
        if (String(existing[i][0]).trim().toLowerCase() === username.toLowerCase()) {
          return createResponse(false, `Username '${username}' already exists.`);
        }
      }
    }

    const hashed = hashPassword(password);
    sheet.appendRow([username, hashed, role, status]);
    sheet.getRange(sheet.getLastRow(), 2).setNumberFormat('@');
    logAuditAction('CREATE_USER', 'Users', username, username, '', `User '${username}' (${role}) created with hashed password`);
    return createResponse(true, `User '${username}' created successfully.`);
  } catch (err) {
    return createResponse(false, 'Failed to create user: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Updates an existing user (role/status/password reset).
 * Requires MASTER "admin" password confirmation (not other Super Admins).
 * Master "admin" password can NEVER be changed here — only via changeOwnPassword by admin.
 * Password resets for other users do not need the target user's old password (master only).
 */
function updateUser(userData) {
  userData = userData || {};
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) return createResponse(false, 'System busy. Try again.');
  try {
    // Only master admin password authorizes privileged user edits
    if (!confirmMasterAdminPassword(userData.adminPassword)) {
      return createResponse(false, 'Invalid master admin password. Only the master admin password authorizes this action.');
    }

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return createResponse(false, 'Users sheet not found.');

    const username = String(userData.username || '').trim();
    if (!username) return createResponse(false, 'Username is required.');
    const targetIsMaster = isMasterAdminUsername(username);

    const wantsPasswordChange = userData.password !== undefined && userData.password !== null &&
      String(userData.password).trim() !== '';

    // Hard lock: no one may set master admin password through user management
    if (targetIsMaster && wantsPasswordChange) {
      return createResponse(false, 'The master "admin" password can only be changed by admin while signed in (Account → Change Password), and requires the current password.');
    }

    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0] || '').trim().toLowerCase() === username.toLowerCase()) {
        let newPasswordStored = String(data[i][1] || '').trim().replace(/^'/, '');
        if (wantsPasswordChange && !targetIsMaster) {
          const plain = String(userData.password).trim();
          if (plain.length < 8) {
            return createResponse(false, 'New password must be at least 8 characters.');
          }
          newPasswordStored = hashPassword(plain);
        }

        let newRole = userData.role !== undefined && userData.role !== null && String(userData.role).trim() !== ''
          ? roleToPermissions(userData.role).roleLabel
          : roleToPermissions(data[i][2]).roleLabel;
        let newStatus = userData.status !== undefined && userData.status !== null && String(userData.status).trim() !== ''
          ? String(userData.status).trim()
          : String(data[i][3] || 'Active').trim();

        // Protect built-in admin role/status
        if (targetIsMaster) {
          newRole = 'Super Admin';
          if (String(newStatus).toLowerCase() !== 'active') {
            return createResponse(false, 'The admin account must remain Active.');
          }
        }

        sheet.getRange(i + 1, 2).setValue(newPasswordStored).setNumberFormat('@');
        sheet.getRange(i + 1, 3).setValue(newRole);
        sheet.getRange(i + 1, 4).setValue(newStatus);

        const pwdNote = wantsPasswordChange && !targetIsMaster ? ', password=reset' : ', password=unchanged';
        logAuditAction('UPDATE_USER', 'Users', username, username, '', `Updated role=${newRole}, status=${newStatus}${pwdNote}`);
        return createResponse(true, `User '${username}' updated successfully.`);
      }
    }
    return createResponse(false, `User '${username}' not found.`);
  } catch (err) {
    return createResponse(false, 'Failed to update user: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Deletes a portal user. Requires Super Admin password.
 */
function deleteUser(username, adminPassword) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) return createResponse(false, 'System busy. Try again.');
  try {
    if (!confirmMasterAdminPassword(adminPassword)) {
      return createResponse(false, 'Invalid master admin password. Access denied.');
    }

    const cleanName = String(username || '').trim();
    if (!cleanName) return createResponse(false, 'Username is required.');
    if (isMasterAdminUsername(cleanName)) {
      return createResponse(false, 'The built-in admin account cannot be deleted.');
    }

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return createResponse(false, 'Users sheet not found.');
    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === cleanName.toLowerCase()) {
        sheet.deleteRow(i + 1);
        logAuditAction('DELETE_USER', 'Users', cleanName, cleanName, '', `User '${cleanName}' deleted`);
        return createResponse(true, `User '${cleanName}' removed successfully.`);
      }
    }
    return createResponse(false, `User '${cleanName}' not found.`);
  } catch (err) {
    return createResponse(false, 'Failed to delete user: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

// ==============================================================================
// UTILITIES & HELPER FUNCTIONS
// ==============================================================================

/**
 * Extracts the trailing serial number from an ID like WP-2026-00012 or SO-2026-1001.
 * Returns null if no numeric serial is present.
 */
function parseRecordSerial(idValue) {
  const s = String(idValue || '').trim();
  if (!s) return null;
  // Match trailing digits after last hyphen, or pure integer
  const m = s.match(/(\d+)\s*$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return isNaN(n) ? null : n;
}

/**
 * Scans column A of a sheet and returns the highest serial number found
 * for the given prefix (e.g. "WP" or "SO"). Year-agnostic so sequences
 * never reset incorrectly and support values above 999 / 9999.
 */
function getLastSerialNum(sheet, prefix) {
  if (!sheet || sheet.getLastRow() <= 1) return 0;
  const lastRow = sheet.getLastRow();
  const numRows = lastRow - 1; // data rows only
  if (numRows < 1) return 0;

  const firstColValues = sheet.getRange(2, 1, numRows, 1).getValues();
  const prefixUpper = String(prefix || '').toUpperCase();
  let maxSeq = 0;

  firstColValues.forEach(row => {
    const idStr = String(row[0] || '').trim();
    if (!idStr) return;
    // Accept PREFIX-YYYY-##### or PREFIX-#####
    const upper = idStr.toUpperCase();
    if (prefixUpper && upper.indexOf(prefixUpper) !== 0) return;
    const seq = parseRecordSerial(idStr);
    if (seq !== null && seq > maxSeq) maxSeq = seq;
  });

  return maxSeq;
}

/**
 * Returns the latest entry date (YYYY-MM-DD) found in a date column (1-based).
 * Used as a fallback when serial numbers are missing.
 */
function getLatestEntryDate(sheet, dateColIndex1Based) {
  if (!sheet || sheet.getLastRow() <= 1) return '';
  const lastRow = sheet.getLastRow();
  const numRows = lastRow - 1;
  if (numRows < 1) return '';

  const col = Math.max(1, dateColIndex1Based || 1);
  const values = sheet.getRange(2, col, numRows, 1).getValues();
  let latest = '';
  values.forEach(row => {
    const d = formatDateValue(row[0]);
    if (d && (!latest || d > latest)) latest = d;
  });
  return latest;
}

/**
 * Sort comparator: DATE descending, then SN descending.
 */
function compareBySerialThenDate(aId, bId, aDate, bDate) {
  return compareByDateThenSerial(aDate, bDate, aId, bId);
}

/** Primary: newer date first; Secondary: higher SN first */
function compareByDateThenSerial(aDate, bDate, aId, bId) {
  const da = toSortableDate(aDate);
  const db = toSortableDate(bDate);
  if (da && db && da !== db) return db.localeCompare(da); // date DESC
  if (db && !da) return 1;
  if (da && !db) return -1;
  const sa = parseRecordSerial(aId);
  const sb = parseRecordSerial(bId);
  if (sa !== null && sb !== null && sa !== sb) return sb - sa; // SN DESC
  if (sa !== null && sb === null) return -1;
  if (sa === null && sb !== null) return 1;
  return String(bId || '').localeCompare(String(aId || ''));
}

/**
 * Generates next sequential ID as a plain serial number (no prefix).
 * Kept for backward compatibility; prefer generateNextPlainSerial.
 */
function generateNextID(sheet, prefix) {
  return String(generateNextPlainSerial(sheet));
}

/**
 * Prevents formula injection and strips control characters from input strings.
 * Does not alter legitimate field content beyond spreadsheet-safety prefixes.
 */
function sanitizeInput(val) {
  if (val === undefined || val === null) return '';
  let str = String(val).trim();
  // Strip C0 control chars except tab/newline
  str = str.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  // Neutralize spreadsheet formula injection
  if (/^[=+\-@]/.test(str)) {
    str = "'" + str;
  }
  // Cap extreme length (DoS / sheet cell limits)
  if (str.length > 50000) str = str.substring(0, 50000);
  return str;
}

/**
 * Formats Badge Numbers cleanly
 */
function formatBadgeNumber(val) {
  if (!val) return '';
  return String(val).trim();
}

/**
 * Standard Date Value Formatter (YYYY-MM-DD)
 */

/**
 * Parse mixed date formats into a Date (local).
 * Supports: Date, yyyy-mm-dd, mm/dd/yyyy, dd/mm/yyyy, mm-dd-yyyy, dd-mm-yyyy.
 * Legacy sheet values that look like dd/mm/yyyy are converted to real calendar dates
 * so formatDateMDY can emit mm/dd/yyyy. Year is never greater than 2026.
 */
function parseFlexibleDate(val) {
  if (val === null || val === undefined || val === '') return null;
  if (Object.prototype.toString.call(val) === '[object Date]') {
    return isNaN(val.getTime()) ? null : clampDateYear(val);
  }
  // Sheets sometimes returns serial numbers
  if (typeof val === 'number' && isFinite(val)) {
    const epoch = new Date(1899, 11, 30);
    const d = new Date(epoch.getTime() + Math.round(val) * 86400000);
    return isNaN(d.getTime()) ? null : clampDateYear(d);
  }
  const s = String(val).trim();
  if (!s) return null;

  // ISO yyyy-mm-dd (optional time)
  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
  if (m) {
    let y = Number(m[1]);
    if (y > 2026) y = 2026;
    const d = new Date(y, Number(m[2]) - 1, Number(m[3]));
    return isNaN(d.getTime()) ? null : d;
  }

  // a/b/yyyy or a-b-yyyy — mixed mm/dd and dd/mm appear in the same sheets
  m = s.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})$/);
  if (m) {
    let a = parseInt(m[1], 10);
    let b = parseInt(m[2], 10);
    let y = parseInt(m[3], 10);
    if (y > 2026) y = 2026;

    function makeValid(month, day) {
      if (month < 1 || month > 12 || day < 1 || day > 31) return null;
      const d = new Date(y, month - 1, day);
      if (isNaN(d.getTime())) return null;
      if (d.getFullYear() !== y || d.getMonth() !== month - 1 || d.getDate() !== day) return null;
      return d;
    }

    let chosen = null;
    if (a > 12 && b <= 12) {
      // Must be dd/mm
      chosen = makeValid(b, a);
    } else if (b > 12 && a <= 12) {
      // Must be mm/dd
      chosen = makeValid(a, b);
    } else {
      // Ambiguous (e.g. 07/11/2026, 12/07/2026, 8/9/2026):
      // Prefer the interpretation that is NOT far in the future (fixes Dec/Nov chart spill)
      const asMd = makeValid(a, b); // mm/dd
      const asDm = makeValid(b, a); // dd/mm
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      const maxFutureMs = 21 * 86400000; // allow up to ~3 weeks ahead
      function isFarFuture(d) {
        return d && (d.getTime() - today.getTime() > maxFutureMs);
      }
      if (asMd && asDm) {
        const fMd = isFarFuture(asMd);
        const fDm = isFarFuture(asDm);
        if (fMd && !fDm) chosen = asDm;
        else if (fDm && !fMd) chosen = asMd;
        else {
          // Both reasonable — prefer closer to today
          const distMd = Math.abs(asMd.getTime() - today.getTime());
          const distDm = Math.abs(asDm.getTime() - today.getTime());
          chosen = distMd <= distDm ? asMd : asDm;
        }
      } else {
        chosen = asMd || asDm;
      }
    }
    return chosen;
  }

  const d = new Date(s);
  return isNaN(d.getTime()) ? null : clampDateYear(d);
}

/** Cap calendar year at 2026 */
function clampDateYear(d) {
  if (!d || isNaN(d.getTime())) return d;
  if (d.getFullYear() > 2026) {
    return new Date(2026, d.getMonth(), d.getDate());
  }
  return d;
}

/** Canonical display + sheet storage: mm/dd/yyyy (zero-padded), year ≤ 2026 */
function formatDateMDY(val) {
  const d = parseFlexibleDate(val);
  if (!d) return '';
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const yyyy = Math.min(d.getFullYear(), 2026);
  return mm + '/' + dd + '/' + yyyy;
}

/** Sortable / filter key: yyyy-mm-dd (year capped at 2026) */
function toSortableDate(val) {
  const d = parseFlexibleDate(val);
  if (!d) return '';
  const yyyy = Math.min(d.getFullYear(), 2026);
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return yyyy + '-' + mm + '-' + dd;
}

/**
 * Next SN = current data row count + 1 (header excluded).
 * Also never goes below (max existing serial + 1) so IDs stay unique after deletes.
 */
function generateNextPlainSerial(sheet) {
  if (!sheet || sheet.getLastRow() <= 1) return 1;
  const numRows = sheet.getLastRow() - 1; // data rows only
  let maxSeq = 0;
  try {
    const values = sheet.getRange(2, 1, numRows, 1).getValues();
    values.forEach(function (row) {
      const seq = parseRecordSerial(row[0]);
      if (seq !== null && seq > maxSeq) maxSeq = seq;
    });
  } catch (e) {}
  // Prefer row-count based SN; never reuse an existing higher serial
  return Math.max(numRows, maxSeq) + 1;
}

/** @deprecated use generateNextPlainSerial */
function generateNextObservationSerial(sheet) {
  return generateNextPlainSerial(sheet);
}

/**
 * Find the sheet row (1-based) whose column A serial parses to 1.
 * Falls back to row 2 (first data row) when SN=1 is missing.
 */
function findSerialOneRow(sheet) {
  if (!sheet || sheet.getLastRow() < 2) return 2;
  const numRows = sheet.getLastRow() - 1;
  const values = sheet.getRange(2, 1, numRows, 1).getValues();
  for (let i = 0; i < values.length; i++) {
    const seq = parseRecordSerial(values[i][0]);
    if (seq === 1) return i + 2; // 1-based sheet row
  }
  return 2;
}

/**
 * Format painter: copy cell/column properties from the SN=1 data row onto targetRow.
 * Uses copyTo(PASTE_FORMAT) so font, fill, borders, and number formats match SN 1.
 * @param {GoogleAppsScript.Spreadsheet.Sheet} sheet
 * @param {number} targetRow 1-based
 * @param {number} numCols number of operational columns (13 WP / 16 SO)
 */
function applyFormatFromSerialOne(sheet, targetRow, numCols) {
  if (!sheet || !targetRow || targetRow < 2) return;
  const cols = Math.max(1, numCols || 13);
  let srcRow = findSerialOneRow(sheet);
  // If SN=1 row is the same as target (only one data row), use row 2 when available after append
  if (srcRow === targetRow) {
    if (sheet.getLastRow() >= 2 && targetRow !== 2) srcRow = 2;
    else {
      try {
        sheet.getRange(1, 1, 1, cols).copyFormatToRange(sheet, 1, cols, targetRow, targetRow);
        sheet.getRange(targetRow, 1, 1, cols).setFontWeight('normal').setBackground(null);
      } catch (e) {}
      return;
    }
  }
  try {
    const src = sheet.getRange(srcRow, 1, 1, cols);
    const dst = sheet.getRange(targetRow, 1, 1, cols);
    src.copyTo(dst, SpreadsheetApp.CopyPasteType.PASTE_FORMAT, false);
  } catch (e1) {
    try {
      sheet.getRange(srcRow, 1, 1, cols).copyFormatToRange(sheet, 1, cols, targetRow, targetRow);
    } catch (e2) {
      if (sheet.getLastRow() >= 2) {
        try {
          sheet.getRange(2, 1, 1, cols).copyFormatToRange(sheet, 1, cols, targetRow, targetRow);
        } catch (e3) {}
      }
    }
  }
}

/**
 * Clears content and sets white background on columns from startCol (1-based)
 * through the sheet's last column, for a single row. Keeps sheets clean past
 * the operational schema (WP: from N; SO: from Q).
 */
function clearTrailingColumnsWhite(sheet, rowIndex, startCol1Based) {
  if (!sheet || !rowIndex || rowIndex < 1) return;
  const maxCols = sheet.getMaxColumns();
  const start = Math.max(1, startCol1Based || 1);
  if (start > maxCols) return;
  const numCols = maxCols - start + 1;
  if (numCols < 1) return;
  const range = sheet.getRange(rowIndex, start, 1, numCols);
  range.clearContent();
  range.setBackground('#ffffff');
  range.setBorder(false, false, false, false, false, false);
}

/**
 * Returns yyyy-mm-dd for sorting/filtering (internal).
 * Prefer formatDateMDY() for sheet storage and UI display (mm/dd/yyyy).
 */
function formatDateValue(val) {
  return toSortableDate(val) || '';
}

/**
 * Normalize all date cells in WP + SO sheets to mm/dd/yyyy text + number format.
 * Safe to re-run. Does not change SN or other columns.
 */
function normalizeAllSheetDates() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const report = { workPermits: 0, observations: 0 };

  function fixSheet(sheetName, dateCol1Based) {
    const sheet = ss.getSheetByName(sheetName);
    if (!sheet || sheet.getLastRow() < 2) return 0;
    const n = sheet.getLastRow() - 1;
    const range = sheet.getRange(2, dateCol1Based, n, 1);
    const values = range.getValues();
    let changed = 0;
    for (let i = 0; i < values.length; i++) {
      const formatted = formatDateMDY(values[i][0]);
      if (formatted) {
        values[i][0] = formatted;
        changed++;
      }
    }
    range.setNumberFormat('@'); // text so format is preserved
    range.setValues(values);
    range.setNumberFormat('m/d/yyyy');
    return changed;
  }

  report.workPermits = fixSheet(CONFIG.SHEETS.WORK_PERMITS, 5); // E = WP Date
  report.observations = fixSheet(CONFIG.SHEETS.SAFETY_OBSERVATIONS, 2); // B = Obs Date
  try {
    logAuditAction('MAINT', 'Sheets', 'normalize-dates', '', '',
      'Normalized dates to mm/dd/yyyy; WP=' + report.workPermits + ' SO=' + report.observations);
  } catch (e) {}
  return createResponse(true, 'Dates normalized to mm/dd/yyyy', report);
}

/**
 * Renumber column A SN to 1..N by current row order (top to bottom).
 * Optional: pass { sortByDate: true } to sort rows by date DESC then renumber.
 */
function renumberSheetSerials(options) {
  options = options || {};
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const results = {};

  function renumber(sheetName, dateCol1Based) {
    const sheet = ss.getSheetByName(sheetName);
    if (!sheet || sheet.getLastRow() < 2) {
      results[sheetName] = 0;
      return;
    }
    const lastRow = sheet.getLastRow();
    const lastCol = Math.max(sheet.getLastColumn(), dateCol1Based || 1);
    const numRows = lastRow - 1;
    const data = sheet.getRange(2, 1, numRows, lastCol).getValues();

    if (options.sortByDate) {
      data.sort(function (a, b) {
        return compareByDateThenSerial(a[dateCol1Based - 1], b[dateCol1Based - 1], a[0], b[0]);
      });
    }

    for (let i = 0; i < data.length; i++) {
      data[i][0] = i + 1; // SN = 1..N
      if (dateCol1Based && data[i][dateCol1Based - 1]) {
        const fd = formatDateMDY(data[i][dateCol1Based - 1]);
        if (fd) data[i][dateCol1Based - 1] = fd;
      }
    }

    sheet.getRange(2, 1, numRows, lastCol).setValues(data);
    sheet.getRange(2, 1, numRows, 1).setNumberFormat('0');
    if (dateCol1Based) {
      sheet.getRange(2, dateCol1Based, numRows, 1).setNumberFormat('m/d/yyyy');
    }
    results[sheetName] = numRows;
  }

  renumber(CONFIG.SHEETS.WORK_PERMITS, 5);
  renumber(CONFIG.SHEETS.SAFETY_OBSERVATIONS, 2);
  try {
    logAuditAction('MAINT', 'Sheets', 'renumber-sn', '', '',
      'Renumbered SN by row count; ' + JSON.stringify(results));
  } catch (e) {}
  return createResponse(true, 'Serial numbers renumbered', results);
}

/**
 * Standard Timestamp Formatter (YYYY-MM-DD HH:MM:SS)
 */
function formatTimestamp(val) {
  if (!val) return '';
  let d = val instanceof Date ? val : new Date(val);
  if (isNaN(d.getTime())) return String(val);
  
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const hh = String(d.getHours()).padStart(2, '0');
  const min = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  
  return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
}

/**
 * Structured API Response Producer
 */
function createResponse(success, message, data, errorCode) {
  return {
    success: success,
    message: message || '',
    data: data || null,
    errorCode: errorCode || null,
    serverTimestamp: new Date().toISOString()
  };
}

// ==============================================================================
// PRODUCTION HEALTH / SELF-TEST (read-only; does not mutate WP/SO data rows)
// ==============================================================================

/**
 * Run from Apps Script editor after deploy. Validates core modules without
 * writing to Work Permit or Safety Observation record sheets.
 */
function runProductionSelfTest() {
  const results = [];
  function ok(name, pass, detail) {
    results.push({ name: name, pass: !!pass, detail: detail || '' });
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    ok('Spreadsheet bound', !!ss, ss ? ss.getName() : 'none');

    const needSheets = [
      CONFIG.SHEETS.WORK_PERMITS,
      CONFIG.SHEETS.SAFETY_OBSERVATIONS,
      CONFIG.SHEETS.USERS,
      CONFIG.SHEETS.AUDIT_LOG,
      CONFIG.SHEETS.SETTINGS,
      CONFIG.SHEETS.IDEMPOTENCY
    ];
    needSheets.forEach(function (name) {
      const sh = ss.getSheetByName(name);
      ok('Sheet: ' + name, !!sh, sh ? 'ok' : 'MISSING');
    });

    // Auth helpers
    ok('hash/verify password', (function () {
      const h = hashPassword('SelfTest!99xx');
      return isPasswordHashed(h) && verifyPassword('SelfTest!99xx', h) && !verifyPassword('wrong', h);
    })(), '');

    ok('salt uniqueness', (function () {
      const a = generateSalt();
      const b = generateSalt();
      return a.length === 32 && b.length === 32 && a !== b && /^[0-9a-f]+$/i.test(a);
    })(), '');

    ok('sanitize formula injection', sanitizeInput('=CMD()') === "'=CMD()", sanitizeInput('=CMD()'));
    ok('sanitize control strip', sanitizeInput('a\u0000b').indexOf('\u0000') === -1, '');

    // Date engine
    ok('date day>12 dd/mm', formatDateMDY('16/08/2025') === '08/16/2025', formatDateMDY('16/08/2025'));
    ok('date year clamp', formatDateMDY('08/16/2029') === '08/16/2026', formatDateMDY('08/16/2029'));
    ok('date ISO', formatDateMDY('2025-03-09') === '03/09/2025', formatDateMDY('2025-03-09'));
    // Ambiguous: prefer not-far-future (12/07/2026 should be Jul 12, not Dec 7, when "today" is mid-2026)
    ok('date ambiguous 12/07', (function () {
      const d = parseFlexibleDate('12/07/2026');
      return d && d.getMonth() === 6 && d.getDate() === 12; // July 12
    })(), formatDateMDY('12/07/2026'));

    // Classification smoke
    const cls = classifyObservation('Worker not wearing helmet and safety gloves.');
    ok('classify PPE', cls.matchedCategories.indexOf('PPE') !== -1, JSON.stringify(cls.matchedCategories));
    const cls2 = classifyObservation('Worker was wearing helmet, gloves, goggles and safety shoes.');
    ok('classify PPE once', (cls2.matchedCategories.filter(function (c) { return c === 'PPE'; }).length <= 1), JSON.stringify(cls2.matchedCategories));

    // Master admin protection
    ok('isMasterAdminUsername', isMasterAdminUsername('admin') && !isMasterAdminUsername('other'), '');

    // requireAuth rejects empty token
    const noAuth = requireAuth('', 'view');
    ok('requireAuth blocks anonymous', !noAuth.ok, noAuth.response && noAuth.response.errorCode);
    const badAuth = requireAuth('not-a-real-token', 'view');
    ok('requireAuth rejects invalid session', !badAuth.ok, badAuth.response && badAuth.response.errorCode);

    // Idempotency index round-trip (cache/props only — no sheet pollution beyond normal store)
    (function () {
      const id = 'selftest-' + Utilities.getUuid();
      const payload = { success: true, message: 'selftest', data: { id: id }, errorCode: null };
      storeIdempotency(id, payload);
      const hit = checkIdempotency(id);
      ok('idempotency indexed replay', hit && hit.success && hit.message === 'selftest', hit ? hit.message : 'null');
    })();

    // WP/SO column counts unchanged
    ok('WP schema cols=14', CONFIG.WP.COLS === 14, String(CONFIG.WP.COLS));
    ok('SO schema cols=16', CONFIG.SO.COLS === 16, String(CONFIG.SO.COLS));
    ok('WP_ARCHIVE sheet name configured', !!CONFIG.SHEETS.WP_ARCHIVE, CONFIG.SHEETS.WP_ARCHIVE);

  } catch (err) {
    ok('self-test exception', false, String(err));
  }

  const passed = results.filter(function (r) { return r.pass; }).length;
  const summary = 'Production self-test: ' + passed + '/' + results.length + ' passed';
  Logger.log(summary);
  results.forEach(function (r) {
    Logger.log((r.pass ? 'PASS' : 'FAIL') + ' — ' + r.name + (r.detail ? ' (' + r.detail + ')' : ''));
  });
  return createResponse(passed === results.length, summary, { results: results });
}
