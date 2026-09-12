/**
 * Учёт Отчётов Возвещателей — защищённый прокси-сервер (Cloudflare Worker)
 * -------------------------------------------------------------------------
 * Задача этого файла: спрятать секретный ключ JSONBin.io от браузера и
 * добавить настоящую проверку пароля на сервере (а не в коде страницы,
 * как было раньше — с открытым ключом и паролями в чистом виде).
 *
 * ПЕРЕД ДЕПЛОЕМ:
 * 1. На JSONBin.io перевыпустите (rotate) X-Master-Key для существующего
 *    бина — старый ключ уже был виден в публичном репозитории и считается
 *    скомпрометированным. Сами данные (отчёты) при этом не теряются.
 * 2. В Cloudflare Dashboard -> ваш Worker -> Settings -> Variables and
 *    Secrets добавьте два СЕКРЕТА (тип "Secret", не "Text"):
 *      JSONBIN_KEY     — новый X-Master-Key от JSONBin.io
 *      SESSION_SECRET  — любая длинная случайная строка (40+ символов),
 *                        придумайте сами — она подписывает токены входа.
 *
 * BIN_ID и разрешённый источник (домен сайта) ниже захардкожены — поменяйте,
 * если у вас другой BIN_ID или другой домен/поддомен.
 */

const BIN_ID = "6aa3daeeac6210605ac031af";
const ALLOWED_ORIGIN = "https://nifork-oss.github.io";
const TOKEN_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000; // 30 дней

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

/* ============== крипто-утилиты (пароли + токены) ============== */

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(len = 16) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return toHex(arr.buffer);
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return toHex(buf);
}

async function hashPassword(password) {
  const salt = randomHex();
  const hash = await sha256Hex(salt + password);
  return `s2$${salt}$${hash}`;
}

async function verifyPassword(password, stored) {
  if (!stored) return false;
  if (typeof stored === "string" && stored.startsWith("s2$")) {
    const [, salt, hash] = stored.split("$");
    const check = await sha256Hex(salt + password);
    return check === hash;
  }
  return stored === password;
}

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlToBytes(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function hmacKey(env) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signToken(payload, env) {
  const key = await hmacKey(env);
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return `${body}.${b64url(sig)}`;
}

async function verifyToken(token, env) {
  try {
    const [body, sig] = token.split(".");
    if (!body || !sig) return null;
    const key = await hmacKey(env);
    const valid = await crypto.subtle.verify("HMAC", key, b64urlToBytes(sig), new TextEncoder().encode(body));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(body)));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

async function getAuthUser(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) return null;
  return await verifyToken(token, env);
}

/* ============== доступ к JSONBin (с повторными попытками) ============== */

async function fetchJsonBinWithRetry(url, options, attempts = 3) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, options);
      if (res.ok) return res;
      lastErr = new Error(`JSONBin временно недоступен (код ${res.status})`);
    } catch (e) {
      lastErr = e;
    }
    if (i < attempts - 1) {
      await new Promise((resolve) => setTimeout(resolve, 400 * (i + 1)));
    }
  }
  throw lastErr;
}

/* ============== сжатие (чтобы уместиться в лимит JSONBin в 1 МБ) ============== */
// JSONBin бесплатного тарифа ограничивает обычный бин 1 МБ. С реальной базой
// отчётов (тысячи записей) несжатый JSON легко превышает лимит. Сжимаем перед
// отправкой и разжимаем при чтении — прозрачно для остального кода worker'а
// и полностью прозрачно для сайта (он этого вообще не видит).

function bufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function gzipCompress(str) {
  const stream = new Blob([str]).stream().pipeThrough(new CompressionStream("gzip"));
  const buffer = await new Response(stream).arrayBuffer();
  return bufferToBase64(buffer);
}

async function gzipDecompress(base64) {
  const buffer = base64ToBuffer(base64);
  const stream = new Blob([buffer]).stream().pipeThrough(new DecompressionStream("gzip"));
  const text = await new Response(stream).text();
  return JSON.parse(text);
}

async function readBoard(env) {
  const res = await fetchJsonBinWithRetry(`https://api.jsonbin.io/v3/b/${BIN_ID}/latest`, {
    headers: { "X-Master-Key": env.JSONBIN_KEY },
  });
  const data = await res.json();
  const raw = data.record;
  let record;

  if (raw && typeof raw === "object" && typeof raw.gzip === "string") {
    // Текущий (сжатый) формат хранения.
    record = await gzipDecompress(raw.gzip);
  } else if (Array.isArray(raw)) {
    // Миграция самого старого формата: раньше весь бин был просто массивом
    // отчётов (без пользователей вообще — те жили только в localStorage браузера).
    record = { users: [], reports: raw };
  } else {
    // Несжатый объект (переходный формат до включения сжатия).
    record = raw && typeof raw === "object" ? raw : {};
  }

  if (!Array.isArray(record.users)) record.users = [];
  if (!Array.isArray(record.reports)) record.reports = [];
  if (!record.ppNorms || typeof record.ppNorms !== "object" || Array.isArray(record.ppNorms)) record.ppNorms = {};
  if (!Array.isArray(record.mergeLog)) record.mergeLog = [];
  if (!record.reportStatus || typeof record.reportStatus !== "object" || Array.isArray(record.reportStatus)) record.reportStatus = {};
  if (!record.personMeta || typeof record.personMeta !== "object" || Array.isArray(record.personMeta)) record.personMeta = {};

  // Если пользователей ещё нет вообще — сеем ОДНОГО супер-админа, чтобы был
  // хоть один вход в систему. Пароль временный, специально не хранится в
  // коде — задаётся один раз при первом реальном запуске и должен быть
  // сразу же сменён через "Сброс пароля" в панели "Аккаунты".
  if (record.users.length === 0 && env.SEED_ADMIN_EMAIL && env.SEED_ADMIN_PASSWORD) {
    const pass = await hashPassword(env.SEED_ADMIN_PASSWORD);
    record.users.push({ email: env.SEED_ADMIN_EMAIL, pass, group: "1", role: "superadmin" });
    await writeBoard(env, record);
  }

  return record;
}

async function writeBoard(env, data) {
  const gzip = await gzipCompress(JSON.stringify(data));
  await fetchJsonBinWithRetry(`https://api.jsonbin.io/v3/b/${BIN_ID}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Master-Key": env.JSONBIN_KEY },
    body: JSON.stringify({ gzip }),
  });
}

function stripPasswords(users) {
  return (users || []).map((u) => ({ email: u.email, group: u.group, role: u.role, approved: u.approved === undefined ? true : !!u.approved }));
}

/* ============== обработчик запросов ============== */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    try {
      // Регистрация нового пользователя. Роль всегда "user" — админом можно
      // стать только через "Аккаунты" у супер-админа, не при регистрации.
      if (path === "/register" && request.method === "POST") {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "").trim();
        const group = String(body.group || "").trim().slice(0, 20);
        if (!email || !password || !group) return json({ error: "Заполните все поля" }, 400);
        const record = await readBoard(env);
        if (record.users.some((u) => u.email.toLowerCase() === email))
          return json({ error: "Пользователь с таким email уже существует" }, 400);
        const pass = await hashPassword(password);
        // Новый аккаунт не подтверждён по умолчанию — доступ к данным группы
        // открывает админ/супер-админ вручную в панели "Аккаунты".
        record.users.push({ email, pass, group, role: "user", approved: false });
        await writeBoard(env, record);
        const token = await signToken({ email, role: "user", group, exp: Date.now() + TOKEN_LIFETIME_MS }, env);
        return json({ token, email, role: "user", group, approved: false });
      }

      // Вход
      if (path === "/login" && request.method === "POST") {
        const body = await request.json();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "").trim();
        const record = await readBoard(env);
        const user = record.users.find((u) => u.email.toLowerCase() === email);
        if (!user || !(await verifyPassword(password, user.pass))) {
          return json({ error: "Неверный email или пароль" }, 401);
        }
        // Мягкая миграция: если пароль ещё хранился в открытом виде — хэшируем при первом входе.
        if (!(typeof user.pass === "string" && user.pass.startsWith("s2$"))) {
          user.pass = await hashPassword(password);
          await writeBoard(env, record);
        }
        // Мягкая миграция: у аккаунтов, созданных до появления подтверждения,
        // считаем approved=true, чтобы никого из уже работающих не заблокировать.
        const isApproved = user.approved === undefined ? true : !!user.approved;
        const token = await signToken({ email: user.email, role: user.role, group: user.group, exp: Date.now() + TOKEN_LIFETIME_MS }, env);
        return json({ token, email: user.email, role: user.role, group: user.group, approved: isApproved });
      }

      // Всё, что ниже, требует действительного токена входа
      const auth = await getAuthUser(request, env);
      if (!auth) return json({ error: "Требуется вход" }, 401);
      const isAdmin = auth.role === "admin" || auth.role === "superadmin";
      const isSuperadmin = auth.role === "superadmin";

      // Получение данных приложения (пароли никогда не отдаются клиенту)
      if (path === "/appdata" && request.method === "GET") {
        const record = await readBoard(env);
        return json({
          data: { reports: record.reports, users: stripPasswords(record.users), ppNorms: record.ppNorms || {}, mergeLog: record.mergeLog || [], reportStatus: record.reportStatus || {}, personMeta: record.personMeta || {} },
          role: auth.role,
          email: auth.email,
        });
      }

      // Сохранение данных приложения
      if (path === "/appdata" && request.method === "PUT") {
        const incoming = await request.json();
        const record = await readBoard(env);

        // Отчёты может сохранять любой вошедший пользователь (это основной
        // рабочий процесс приложения — заполнение своих отчётов).
        if (Array.isArray(incoming.reports)) {
          record.reports = incoming.reports;
        }

        // Норма часов для ПП по месяцам ("YYYY-MM" -> число часов) — задаёт
        // только админ/супер-админ, она общая на всех ПП в конкретном месяце.
        if (incoming.ppNorms && typeof incoming.ppNorms === "object" && !Array.isArray(incoming.ppNorms)) {
          if (!isAdmin) {
            return json({ error: "Недостаточно прав для изменения нормы ПП" }, 403);
          }
          record.ppNorms = incoming.ppNorms;
        }

        // Журнал объединений карточек — тоже только админ/супер-админ, чтобы
        // рядовой пользователь не мог случайно (или намеренно) склеить или
        // расклеить чужие карточки.
        if (Array.isArray(incoming.mergeLog)) {
          if (!isAdmin) {
            return json({ error: "Недостаточно прав для изменения истории объединений" }, 403);
          }
          record.mergeLog = incoming.mergeLog;
        }

        // Статус "сдан ли отчёт за месяц" — по месяцам ("YYYY-MM"), с двумя
        // источниками: какие группы уже отметили свой отчёт сданным, и
        // ручной флаг админа "отправлено" на весь месяц целиком.
        // Админ может менять всё; рядовой пользователь (ответственный за
        // группу) — только отметку СВОЕЙ группы, ничего больше.
        if (incoming.reportStatus && typeof incoming.reportStatus === "object" && !Array.isArray(incoming.reportStatus)) {
          if (isAdmin) {
            record.reportStatus = incoming.reportStatus;
          } else {
            const myGroup = String(auth.group || "");
            const current = record.reportStatus || {};
            const merged = { ...current };
            for (const [monthKey, incEntry] of Object.entries(incoming.reportStatus)) {
              const curEntry = current[monthKey] || { adminOverride: false, groupsSubmitted: [] };
              const incGroups = Array.isArray(incEntry.groupsSubmitted) ? incEntry.groupsSubmitted.map(String) : [];
              const curGroups = Array.isArray(curEntry.groupsSubmitted) ? curEntry.groupsSubmitted.map(String) : [];
              const changed = new Set([
                ...incGroups.filter((g) => !curGroups.includes(g)),
                ...curGroups.filter((g) => !incGroups.includes(g)),
              ]);
              const onlyOwnGroupChanged = [...changed].every((g) => g === myGroup);
              const overrideUnchanged = !!incEntry.adminOverride === !!curEntry.adminOverride;
              if (!onlyOwnGroupChanged || !overrideUnchanged) {
                return json({ error: "Можно менять статус сдачи только своей группы" }, 403);
              }
              merged[monthKey] = { adminOverride: !!curEntry.adminOverride, groupsSubmitted: incGroups };
            }
            record.reportStatus = merged;
          }
        }

        // Личные данные карточки возвещателя (дата рождения/крещения, пол/надежда,
        // контакты), по personId. Доступно любому вошедшему пользователю —
        // карточка теперь открыта и ответственным за группу, не только админам.
        if (incoming.personMeta && typeof incoming.personMeta === "object" && !Array.isArray(incoming.personMeta)) {
          record.personMeta = incoming.personMeta;
        }

        // Список пользователей (роли, сброс пароля, удаление) — только
        // супер-админ. Не-супер-админ, даже редактируя что-то своё, не может
        // изменить себе роль — иначе мог бы сам себя назначить админом.
        if (Array.isArray(incoming.users)) {
          if (!isSuperadmin) {
            return json({ error: "Недостаточно прав для изменения пользователей" }, 403);
          }
          const byEmail = Object.fromEntries(record.users.map((u) => [u.email, u]));
          const newUsersList = [];
          for (const incUser of incoming.users) {
            const existing = byEmail[incUser.email];
            if (incUser.pass) {
              const pass = await hashPassword(incUser.pass);
              newUsersList.push({
                email: incUser.email,
                group: incUser.group ?? (existing ? existing.group : "1"),
                role: incUser.role || (existing ? existing.role : "user"),
                approved: incUser.approved ?? (existing ? existing.approved : false),
                pass,
              });
            } else if (existing) {
              newUsersList.push({
                ...existing,
                group: incUser.group ?? existing.group,
                role: incUser.role ?? existing.role,
                approved: incUser.approved ?? existing.approved,
              });
            }
          }
          record.users = newUsersList;
        }

        await writeBoard(env, record);
        return json({ data: { reports: record.reports, users: stripPasswords(record.users), ppNorms: record.ppNorms || {}, mergeLog: record.mergeLog || [], reportStatus: record.reportStatus || {}, personMeta: record.personMeta || {} } });
      }

      return json({ error: "Not found" }, 404);
    } catch (e) {
      return json({ error: "Внутренняя ошибка сервера: " + e.message }, 500);
    }
  },
};
