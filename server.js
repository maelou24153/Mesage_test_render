"use strict";
const express = require("express"), http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const { promisify } = require("util");
const { WebSocketServer } = require("ws");
const scrypt = promisify(crypto.scrypt);

// ======================= Réglages =======================
const PORT = process.env.PORT || 3000;
const BEHIND_PROXY = process.env.TRUST_PROXY === "1" || !!process.env.RENDER; // Render = derrière un proxy HTTPS
const HOPS = Math.max(1, +process.env.PROXY_HOPS || 1);
const DIR = process.env.DATA_DIR || "data";
const MEDIA = path.join(DIR, "media"), FILE = path.join(DIR, "data.json");
const MAX_MEDIA_BYTES = (+process.env.MAX_MEDIA_MB || 3000) * 1e6;
const SESSION_MS = 7 * 864e5;
fs.mkdirSync(MEDIA, { recursive: true, mode: 0o700 });

// ======================= Chiffrement des données sur le disque (AES-256-GCM) =======================
function loadKey() {
  if (process.env.DATA_KEY) {
    if (process.env.DATA_KEY.length < 16) { console.error("❌ DATA_KEY trop courte (16 caractères minimum)."); process.exit(1); }
    return crypto.scryptSync(process.env.DATA_KEY, "messagerie-v1", 32);
  }
  const kf = path.join(DIR, "secret.key");
  if (!fs.existsSync(kf)) fs.writeFileSync(kf, crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
  console.warn("⚠️  DATA_KEY non défini : une clé a été générée dans " + kf + ". Définis DATA_KEY pour mieux protéger les données (la clé ne sera plus à côté d'elles).");
  const k = Buffer.from(fs.readFileSync(kf, "utf8").trim(), "hex");
  if (k.length !== 32) { console.error("❌ " + kf + " est invalide."); process.exit(1); }
  return k;
}
const KEY = loadKey(), MAGIC = Buffer.from("MSG1");
const pack = (s) => {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const b = Buffer.concat([c.update(s, "utf8"), c.final()]);
  return Buffer.concat([MAGIC, iv, c.getAuthTag(), b]);
};
const dec = (b, o) => {
  const d = crypto.createDecipheriv("aes-256-gcm", KEY, b.subarray(o, o + 12));
  d.setAuthTag(b.subarray(o + 12, o + 28));
  return Buffer.concat([d.update(b.subarray(o + 28)), d.final()]).toString();
};
const unpack = (b) => {
  if (b.subarray(0, 4).equals(MAGIC)) return dec(b, 4);
  if (b[0] === 0x7b) return b.toString(); // JSON en clair (très ancienne version) : sera chiffré à la prochaine sauvegarde
  return dec(b, 0);                       // ancien format chiffré
};

// ======================= Base de données (fichier) =======================
// Objets sans prototype : un pseudo ou un salon nommé "constructor" / "__proto__" ne peut plus rien casser.
const dict = (o) => Object.assign(Object.create(null), o);
let raw = {};
if (fs.existsSync(FILE)) {
  try { raw = JSON.parse(unpack(fs.readFileSync(FILE))); }
  catch { console.error("❌ Impossible de lire " + FILE + " (mauvaise clé ?). Arrêt pour ne rien écraser."); process.exit(1); }
}
const db = {
  users: dict(raw.users), rooms: dict(raw.rooms), dms: dict(raw.dms), sessions: dict(raw.sessions),
  secret: raw.secret || crypto.randomBytes(32).toString("hex"),
};
for (const r in db.rooms) if (!Array.isArray(db.rooms[r].history)) db.rooms[r].history = [];
for (const k in db.users) db.users[k].blocked = db.users[k].blocked || [];

let timer;
function flush() {
  const day = new Date().toISOString().slice(0, 10), bak = path.join(DIR, `backup-${day}.bak`);
  if (fs.existsSync(FILE) && !fs.existsSync(bak)) {            // 1 copie de sauvegarde par jour (seules les vieilles copies tournent, jamais les messages)
    fs.copyFileSync(FILE, bak);
    const old = fs.readdirSync(DIR).filter((f) => /^backup-.*\.bak$/.test(f)).sort().slice(0, -60);
    old.forEach((f) => fs.unlinkSync(path.join(DIR, f)));
  }
  fs.writeFileSync(FILE + ".tmp", pack(JSON.stringify(db)), { mode: 0o600 });
  fs.renameSync(FILE + ".tmp", FILE);
}
const save = () => { clearTimeout(timer); timer = setTimeout(() => { try { flush(); } catch (e) { console.error("sauvegarde:", e.message); } }, 500); };
const stop = () => { try { flush(); } catch {} process.exit(0); };
process.on("SIGTERM", stop); process.on("SIGINT", stop);
process.on("uncaughtException", (e) => { console.error("FATAL:", e); try { flush(); } catch {} process.exit(1); });
process.on("unhandledRejection", (e) => console.error("promesse rejetée:", e && e.message));

// ======================= Numéros uniques à 6 chiffres =======================
const idx = Object.create(null); // numéro -> clé du compte
const genId = () => { let n; do n = String(100000 + crypto.randomInt(900000)); while (idx[n]); return n; };
for (const k in db.users) { const u = db.users[k]; if (!u.id) u.id = genId(); u.id = String(u.id); idx[u.id] = k; }
save();

// ======================= Utilitaires =======================
const BAD = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F​‎‏‪-‮⁠-⁩﻿]/g; // caractères de contrôle et d'inversion de texte
const str = (s, n) => (typeof s === "string" ? s.slice(0, n) : "");
const clean = (s, n) => str(s, n).replace(BAD, "");
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const dmKey = (a, b) => [a.toLowerCase(), b.toLowerCase()].sort().join("|");
const NAME_RE = /^[\p{L}0-9_-]{2,20}$/u;
const RESERVED = new Set(["__proto__", "constructor", "prototype", "admin", "administrateur", "moderateur", "system", "systeme", "support", "anonyme", "claude"]);
const EMOJI = ["\u{1F44D}", "❤️", "\u{1F602}", "\u{1F62E}"];
const COMMON = new Set(["password", "motdepasse", "12345678", "123456789", "1234567890", "azertyuiop", "azerty123", "qwertyuiop", "password1", "00000000", "11111111", "iloveyou1"]);
const WEAK_MSG = "Mot de passe trop simple : 8 caractères minimum, évite les mots de passe courants ou uniquement des chiffres.";
const weak = (p, key) => { const l = p.toLowerCase(); return p.length < 8 || COMMON.has(l) || l === key || /^(.)\1+$/.test(p) || (/^\d+$/.test(p) && p.length < 12); };

// ---- Limiteur générique : hit() compte, over() teste ----
const lim = new Map();
function hit(key, max, windowMs, amount = 1) {
  const now = Date.now();
  let f = lim.get(key);
  if (!f || now >= f.until) f = { n: 0, until: now + windowMs };
  f.n += amount; lim.set(key, f);
  return f.n > max;
}
const over = (key, max) => { const f = lim.get(key); return !!f && Date.now() < f.until && f.n >= max; };

// ---- Mots de passe (scrypt, asynchrone pour ne pas bloquer le serveur) ----
const DUMMY = crypto.randomBytes(16).toString("hex");
const hashP = async (p, s) => (await scrypt(p, s, 32)).toString("hex");
const mk = async (p) => { const s = crypto.randomBytes(16).toString("hex"); return { s, h: await hashP(p, s) }; };
const ok = async (o, p) => {
  if (!o || !o.s) { await hashP(p, DUMMY); return false; } // même durée si le compte n'existe pas
  const a = Buffer.from(await hashP(p, o.s), "hex"), b = Buffer.from(String(o.h), "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// ---- Sessions (seul le hachage du jeton est stocké) ----
function newSession(key) {
  const tok = crypto.randomBytes(32).toString("base64url");
  db.sessions[sha(tok)] = { u: key, exp: Date.now() + SESSION_MS };
  const mine = Object.keys(db.sessions).filter((t) => db.sessions[t].u === key).sort((a, b) => db.sessions[a].exp - db.sessions[b].exp);
  mine.slice(0, -10).forEach((t) => delete db.sessions[t]); // 10 appareils maximum
  save();
  return tok;
}

// ======================= Médias =======================
const MT = { "image/jpeg": "jpg", "audio/webm": "webm", "audio/ogg": "ogg", "audio/mp4": "mp4", "audio/mpeg": "mp3", "audio/wav": "wav" };
const L = (b, a, z) => b.subarray(a, z).toString("latin1");
const MAGIC_OK = {
  jpg: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  webm: (b) => b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3,
  ogg: (b) => L(b, 0, 4) === "OggS",
  mp4: (b) => L(b, 4, 8) === "ftyp",
  mp3: (b) => L(b, 0, 3) === "ID3" || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0),
  wav: (b) => L(b, 0, 4) === "RIFF" && L(b, 8, 12) === "WAVE",
};
let mediaBytes = 0;
for (const f of fs.readdirSync(MEDIA)) { try { mediaBytes += fs.statSync(path.join(MEDIA, f)).size; } catch {} }

function saveMedia(d, kind, key) {
  const mm = /^data:([a-z0-9\/]+)(?:;[^,]*)?;base64,([A-Za-z0-9+\/=]+)$/.exec(typeof d === "string" ? d : "");
  if (!mm) return { err: "Fichier refusé." };
  const ext = MT[mm[1]];
  if (!ext || (kind === "img") !== (ext === "jpg")) return { err: "Format non accepté." };
  const buf = Buffer.from(mm[2], "base64");
  if (buf.length > 1.8e6 || buf.length < 16) return { err: "Fichier trop gros." };
  if (!MAGIC_OK[ext](buf)) return { err: "Fichier invalide." };
  if (hit("mc:" + key, 10, 60e3)) return { err: "Trop de fichiers envoyés, attends un peu." };
  if (hit("mb:" + key, 100e6, 864e5, buf.length)) return { err: "Limite d'envoi de fichiers atteinte pour aujourd'hui." };
  if (mediaBytes + buf.length > MAX_MEDIA_BYTES) return { err: "Le stockage du serveur est plein." };
  const id = crypto.randomBytes(16).toString("hex") + "." + ext;
  fs.writeFileSync(path.join(MEDIA, id), buf, { mode: 0o600 });
  mediaBytes += buf.length;
  return { url: "/media/" + id };
}
// Les liens de médias sont signés et expirent au bout de 2 h : un lien qui fuite ne marche pas longtemps.
const sig = (f, e) => crypto.createHmac("sha256", db.secret).update(f + "|" + e).digest("base64url").slice(0, 32);
const signed = (u) => { const e = Math.floor(Date.now() / 1000) + 7200; return `${u}?e=${e}&s=${sig(u.slice(7), e)}`; };
const pub = (m) => { const o = { ...m }; delete o.versions; if (o.url) o.url = signed(o.url); return o; }; // jamais les anciennes versions éditées

// ======================= HTTP =======================
const ipOf = (req) => {
  if (BEHIND_PROXY) {
    const x = String(req.headers["x-forwarded-for"] || "").split(",").map((s) => s.trim()).filter(Boolean);
    if (x.length) return x[Math.max(0, x.length - HOPS)];
  }
  return (req.socket && req.socket.remoteAddress) || "?";
};
const app = express();
app.disable("x-powered-by");
app.use((req, res, next) => {
  const host = String(req.headers.host || "");
  if (!/^[a-z0-9.\-\[\]:]{1,255}$/i.test(host)) return res.sendStatus(400);
  if (hit("http:" + ipOf(req), 300, 60e3)) return res.sendStatus(429);
  if (BEHIND_PROXY && req.headers["x-forwarded-proto"] === "http") return res.redirect(301, "https://" + host + req.url);
  res.set({
    "Content-Security-Policy": `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; media-src 'self'; connect-src 'self' wss://${host} ws://${host}; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000", "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), payment=(), geolocation=(self), microphone=(self)", "Cache-Control": "no-cache",
  });
  next();
});
app.get("/media/:f", (req, res) => {
  const f = String(req.params.f), e = +req.query.e, s = String(req.query.s || "");
  if (!/^[a-f0-9]{32}\.(jpg|webm|ogg|mp4|mp3|wav)$/.test(f)) return res.sendStatus(404);
  const good = Buffer.from(sig(f, e)), got = Buffer.from(s);
  if (!(e > Date.now() / 1000) || good.length !== got.length || !crypto.timingSafeEqual(good, got)) return res.sendStatus(403);
  res.set({ "Cache-Control": "private, max-age=3600", "Content-Disposition": "inline" });
  res.sendFile(path.resolve(MEDIA, f), { dotfiles: "deny" });
});
app.use(express.static(path.join(__dirname, "public"), { dotfiles: "ignore" }));

const server = http.createServer(app);
server.requestTimeout = 30000; server.headersTimeout = 15000;
const conns = new Map();
const wss = new WebSocketServer({
  server, maxPayload: 3 * 1024 * 1024, perMessageDeflate: false,
  verifyClient: ({ origin, req }) => {
    try { if (!origin || new URL(origin).host !== req.headers.host) return false; } catch { return false; } // seulement depuis ce site
    const ip = ipOf(req);
    return (conns.get(ip) || 0) < 10 && !hit("cn:" + ip, 40, 60e3);
  },
});
wss.on("error", (e) => console.error("ws:", e.message));

// ======================= Messagerie =======================
const live = new Map(); // salon -> sockets
const creating = new Set();
const send = (w, o) => { if (w.readyState === 1) w.send(JSON.stringify(o)); };
const all = (r, o) => (live.get(r) || []).forEach((w) => send(w, o));
const names = (r) => [...new Set([...(live.get(r) || [])].map((w) => w.name))];
const err = (ws, text, extra) => send(ws, { type: "err", text, ...extra });
function leave(ws) { const s = live.get(ws.room); if (s) { s.delete(ws); all(ws.room, { type: "users", users: names(ws.room) }); } ws.room = null; }
const kickOthers = (key, keep) => { for (const w of wss.clients) if (w.user === key && w !== keep) w.close(1008, "session"); };
const nameOf = (k) => (db.users[k] ? db.users[k].name : k);

function dmsPayload(key) {
  const threads = {};
  for (const k in db.dms) {
    const [a, b] = k.split("|"); if (a !== key && b !== key) continue;
    threads[nameOf(a === key ? b : a)] = db.dms[k].slice(-200);
  }
  return { type: "dms", dms: threads, blocked: db.users[key].blocked.map(nameOf) };
}

function lookup(ws, q) { // trouver quelqu'un uniquement par son numéro, avec limites contre l'énumération
  const k1 = "lk:" + ws.ip, k2 = "lku:" + ws.user;
  if (over(k1, 8) || over(k2, 20)) { err(ws, "Trop de recherches. Réessaie plus tard."); return null; }
  q = String(q || "").trim().replace(/^#/, "");
  if (!/^\d{6}$/.test(q)) { err(ws, "Entre le numéro à 6 chiffres de la personne."); return null; }
  const t = db.users[idx[q]];
  if (!t) { hit(k1, 8, 15 * 60e3); hit(k2, 20, 36e5); err(ws, "Aucune personne avec ce numéro."); return null; }
  (ws.allowed = ws.allowed || new Set()).add(t.name.toLowerCase());
  return t;
}

let pendingAuth = 0;
async function auth(ws, m) {
  if (ws.user) return;
  const ip = ws.ip, bad = { fatal: 1 };
  if (over("lf:" + ip, 30)) return err(ws, "Trop d'essais. Réessaie dans 15 minutes.", bad);
  if (pendingAuth >= 20) return err(ws, "Serveur occupé, réessaie dans un instant.", bad);
  pendingAuth++;
  try {
    let key, u, tok;
    if (m.mode === "token") {
      const t = str(m.token, 64), s = db.sessions[sha(t)];
      if (!s || s.exp < Date.now() || !db.users[s.u]) { hit("lf:" + ip, 30, 15 * 60e3); return err(ws, "Session expirée, reconnecte-toi.", { fatal: 1, badToken: 1 }); }
      key = s.u; u = db.users[key]; s.exp = Date.now() + SESSION_MS; ws.tok = sha(t);
    } else {
      const nm = clean(m.name, 20).trim(), pass = str(m.pass, 100); key = nm.toLowerCase();
      if (!NAME_RE.test(nm) || RESERVED.has(key)) return err(ws, "Pseudo : 2 à 20 caractères (lettres, chiffres, - ou _).", bad);
      const k1 = "lf:" + ip + ":" + key, k2 = "lfu:" + key;
      if (over(k1, 8) || over(k2, 60)) return err(ws, "Trop d'essais. Réessaie dans 15 minutes.", bad);
      if (m.mode === "register") {
        if (db.users[key]) return err(ws, "Ce pseudo est déjà pris.", bad);
        if (weak(pass, key)) return err(ws, WEAK_MSG, bad);
        if (hit("reg:" + ip, 5, 36e5)) return err(ws, "Trop de comptes créés depuis ta connexion. Réessaie plus tard.", bad);
        const h = await mk(pass);
        if (db.users[key]) return err(ws, "Ce pseudo est déjà pris.", bad);
        u = db.users[key] = { name: nm, ...h, id: genId(), created: Date.now(), blocked: [] }; idx[u.id] = key;
      } else if (m.mode === "login") {
        u = db.users[key];
        if (!(await ok(u, pass))) {
          hit(k1, 8, 15 * 60e3); hit("lf:" + ip, 30, 15 * 60e3); hit(k2, 60, 15 * 60e3);
          return err(ws, "Pseudo ou mot de passe incorrect.", bad);
        }
      } else return;
      lim.delete(k1);
      tok = newSession(key); ws.tok = sha(tok);
    }
    ws.user = key; ws.name = u.name;
    send(ws, { type: "authed", name: u.name, id: u.id, token: tok });
    send(ws, dmsPayload(key));
    save();
  } finally { pendingAuth--; }
}

async function joinRoom(ws, m) {
  const key = ws.user, room = clean(m.room, 30).toLowerCase().replace(/[^a-z0-9-]/g, "") || "general", rp = str(m.roomPass, 100);
  let R = db.rooms[room];
  if (R) {
    if (R.pw && !(R.members || []).includes(key)) { // salon privé : mot de passe demandé une seule fois par personne
      const k = "rf:" + room + ":" + ws.ip;
      if (over(k, 8)) return err(ws, "Trop d'essais sur ce salon. Réessaie dans 15 minutes.");
      if (!(await ok(R.pw, rp))) { hit(k, 8, 15 * 60e3); return err(ws, "Mot de passe du salon incorrect.", { roomPw: room }); }
      (R.members = R.members || []).push(key);
    }
  } else {
    if (creating.has(room)) return err(ws, "Réessaie dans un instant.");
    if (rp && rp.length < 6) return err(ws, "Mot de passe du salon : 6 caractères minimum.");
    if (Object.keys(db.rooms).length >= 5000 || hit("rc:" + key, 10, 864e5)) return err(ws, "Trop de salons créés. Réessaie plus tard.");
    creating.add(room);
    try { R = db.rooms[room] = { history: [], pw: rp ? await mk(rp) : null, members: rp ? [key] : undefined, owner: key, created: Date.now() }; }
    finally { creating.delete(room); }
  }
  leave(ws);
  ws.room = room;
  if (!live.has(room)) live.set(room, new Set());
  live.get(room).add(ws);
  send(ws, { type: "history", room, locked: !!R.pw, more: R.history.length > 200, messages: R.history.slice(-200).map(pub) });
  all(room, { type: "users", users: names(room) });
  save();
}

async function handle(ws, raw) {
  let m; try { m = JSON.parse(raw); } catch { return; }
  if (!m || typeof m !== "object" || Array.isArray(m) || typeof m.type !== "string") return;
  if (!ws.user) { if (m.type === "auth") await auth(ws, m); return; }
  const key = ws.user, u = db.users[key];
  if (!u) return ws.close(1008, "compte");
  const now = Date.now();

  switch (m.type) {
    case "room": return joinRoom(ws, m);

    case "logout": delete db.sessions[ws.tok]; save(); return ws.close(1000, "bye");

    case "passwd": {
      const k1 = "lf:" + ws.ip + ":" + key, nw = str(m.new, 100);
      if (over(k1, 8)) return err(ws, "Trop d'essais. Réessaie dans 15 minutes.");
      if (!(await ok(u, str(m.old, 100)))) { hit(k1, 8, 15 * 60e3); return err(ws, "Ancien mot de passe incorrect."); }
      if (weak(nw, key)) return err(ws, WEAK_MSG);
      Object.assign(u, await mk(nw));
      for (const t in db.sessions) if (db.sessions[t].u === key) delete db.sessions[t]; // déconnecte tous les autres appareils
      kickOthers(key, ws);
      const tok = newSession(key); ws.tok = sha(tok);
      send(ws, { type: "authed", name: u.name, id: u.id, token: tok, changed: 1 });
      return save();
    }

    case "who": { const t = lookup(ws, m.q); if (t) send(ws, { type: "who", name: t.name }); return; }

    case "block": case "unblock": {
      const tk = str(m.name, 20).toLowerCase(), t = db.users[tk];
      if (!t || !(db.dms[dmKey(key, tk)] || (ws.allowed && ws.allowed.has(tk)))) return;
      const i = u.blocked.indexOf(tk);
      if (m.type === "block" && i < 0) u.blocked.push(tk);
      if (m.type === "unblock" && i >= 0) u.blocked.splice(i, 1);
      save(); return send(ws, { type: "blocked", blocked: u.blocked.map(nameOf) });
    }

    case "dm": { // message privé : lisible uniquement par les deux personnes ; il faut connaître le numéro
      const text = clean(m.text, 1000).trim(), q = str(m.to, 20).trim().replace(/^#/, "");
      if (!text) return;
      let t;
      if (/^\d{6}$/.test(q)) t = lookup(ws, q);
      else {
        const tk = q.toLowerCase();
        if ((ws.allowed && ws.allowed.has(tk)) || db.dms[dmKey(key, tk)]) t = db.users[tk];
        else return err(ws, "Pour écrire à quelqu'un, il faut connaître son numéro.");
      }
      if (!t) return;
      const tk = t.name.toLowerCase(), dk = dmKey(key, tk);
      if (tk === key) return err(ws, "Tu ne peux pas t'écrire à toi-même.");
      if (u.blocked.includes(tk)) return err(ws, "Tu as bloqué cette personne. Débloque-la pour lui écrire.");
      if (t.blocked.includes(key)) return err(ws, "Impossible d'envoyer ce message.");
      if (!db.dms[dk] && hit("nc:" + key, 10, 36e5)) return err(ws, "Trop de nouvelles conversations. Réessaie plus tard.");
      if (hit("dm:" + key + ">" + tk, 20, 60e3)) return err(ws, "Doucement…");
      const o = { id: crypto.randomUUID(), from: u.name, to: t.name, text, t: now };
      (db.dms[dk] = db.dms[dk] || []).push(o); save();
      for (const w of wss.clients) if (w.user === key || w.user === tk) send(w, { type: "dm", msg: o });
      return;
    }
  }

  // ---- Actions qui demandent d'être dans un salon ----
  const R = ws.room && db.rooms[ws.room];
  if (!R) return;

  switch (m.type) {
    case "typing": return (live.get(ws.room) || []).forEach((w) => w !== ws && send(w, { type: "typing", name: u.name }));

    case "more": { // anciens messages (rien n'est jamais supprimé)
      const before = +m.before || Infinity, to = str(m.to, 20);
      const list = to ? db.dms[dmKey(key, to)] || [] : R.history;
      const older = list.filter((x) => x.t < before), part = older.slice(-100);
      return send(ws, { type: "more", to: to || null, messages: to ? part : part.map(pub), done: older.length <= 100 });
    }

    case "msg": {
      const k = ["text", "img", "audio", "geo"].includes(m.kind) ? m.kind : "text";
      const msg = { id: crypto.randomUUID(), name: u.name, kind: k, t: now, reactions: {} };
      if (k === "text") { msg.text = clean(m.text, 1000).trim(); if (!msg.text) return; }
      else if (k === "geo") {
        if (typeof m.lat !== "number" || typeof m.lng !== "number" || !(Math.abs(m.lat) <= 90 && Math.abs(m.lng) <= 180)) return;
        msg.lat = Math.round(m.lat * 1e5) / 1e5; msg.lng = Math.round(m.lng * 1e5) / 1e5;
      } else {
        const r = saveMedia(m.data, k, key);
        if (r.err) return err(ws, r.err);
        msg.url = r.url;
      }
      R.history.push(msg); all(ws.room, { type: "msg", msg: pub(msg) }); return save();
    }

    case "react": case "edit": { // pas de suppression possible ; les anciennes versions éditées sont conservées
      const x = R.history.find((h) => h.id === m.id); if (!x) return;
      if (m.type === "react") {
        const e = str(m.emoji, 8); if (!EMOJI.includes(e)) return;
        x.reactions = x.reactions || {};
        const a = (x.reactions[e] = x.reactions[e] || []), i = a.indexOf(u.name);
        i < 0 ? a.push(u.name) : a.splice(i, 1);
        if (!a.length) delete x.reactions[e];
      } else {
        const t = clean(m.text, 1000).trim();
        if (x.name !== u.name || x.kind !== "text" || !t) return;
        x.versions = (x.versions || []).slice(-49); x.versions.push({ text: x.text, t: now });
        x.text = t; x.edited = 1;
      }
      all(ws.room, { type: "upd", msg: pub(x) }); return save();
    }
  }
}

wss.on("connection", (ws, req) => {
  ws.ip = ipOf(req); ws.hits = []; ws.strikes = 0; ws.alive = true; ws.pending = 0; ws.q = Promise.resolve();
  conns.set(ws.ip, (conns.get(ws.ip) || 0) + 1);
  const t = setTimeout(() => { if (!ws.user) ws.close(1008, "auth"); }, 10000); // doit s'identifier vite
  ws.on("pong", () => (ws.alive = true));
  ws.on("error", () => {});
  ws.on("message", (data, isBinary) => {
    if (isBinary || !data || data.length > (ws.user ? 3 * 1024 * 1024 : 2048)) return ws.close(1009, "taille");
    const now = Date.now();
    ws.hits = ws.hits.filter((x) => now - x < 5000); ws.hits.push(now);
    if (ws.hits.length > 15 || (ws.user && hit("ru:" + ws.user, 60, 10e3)) || ws.pending > 20) {
      if (++ws.strikes >= 20) return ws.close(1008, "flood");
      if (now - (ws.lastErr || 0) > 2000) { ws.lastErr = now; err(ws, "Trop de messages, doucement !"); }
      return;
    }
    ws.pending++;
    ws.q = ws.q.then(() => handle(ws, data)).catch((e) => console.error("erreur:", e && e.message)).then(() => { ws.pending--; });
  });
  ws.on("close", () => {
    clearTimeout(t); leave(ws);
    const c = (conns.get(ws.ip) || 1) - 1; c > 0 ? conns.set(ws.ip, c) : conns.delete(ws.ip);
  });
});

setInterval(() => wss.clients.forEach((w) => { if (!w.alive) return w.terminate(); w.alive = false; w.ping(); }), 30000).unref();
setInterval(() => {
  const now = Date.now();
  for (const [k, f] of lim) if (now >= f.until) lim.delete(k);
  for (const t in db.sessions) if (db.sessions[t].exp < now) delete db.sessions[t];
}, 10 * 60e3).unref();

server.listen(PORT, () => console.log("OK"));
