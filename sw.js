/* Service worker de l'espace de prévisualisation chiffré.
 *
 * Le dépôt publié ne contient que des fichiers chiffrés (_p/*.bin). Ce worker
 * intercepte chaque requête du site, va chercher le .bin correspondant et le
 * déchiffre en mémoire avec la clé déposée en IndexedDB par l'écran de mot de passe.
 * Rien n'est jamais écrit en clair sur le disque : fermer la clé (ou changer le mot
 * de passe au build) reverrouille tout.
 *
 * Généré par tools/preview/build.mjs — ne pas éditer dans dist/.
 */
'use strict';

var BASE = '/maquette-c26/';        // ex. '/aixam-maquette/'
var DB = 'preview-c26';            // base IndexedDB portant la clé dérivée
var ENTRY = 'index.html';      // page servie à la racine
var ENC = '_p/';              // dossier des fichiers chiffrés
var MANIFEST = ENC + 'manifest.bin';
var MANIFEST_TTL = 30000;     // revalidation du manifeste (nouveau déploiement)
var MEM_BUDGET = 96 * 1024 * 1024; // plafond du cache mémoire des fichiers déchiffrés

self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });

/* ----------------------------------------------------------------- IndexedDB */

function idbOpen() {
  return new Promise(function (resolve, reject) {
    var req;
    try { req = indexedDB.open(DB, 1); } catch (e) { return reject(e); }
    req.onupgradeneeded = function () {
      if (!req.result.objectStoreNames.contains('k')) req.result.createObjectStore('k');
    };
    req.onsuccess = function () { resolve(req.result); };
    req.onerror = function () { reject(req.error); };
    req.onblocked = function () { reject(new Error('idb blocked')); };
  });
}

var etatIdb = '';   // dernière lecture de la clé : 'ok', 'vide', ou ce qui l'a empêchée

function nom(e) { return (e && (e.name || e.message)) || 'inconnue'; }

function idbGetKey() {
  return idbOpen().then(function (db) {
    return new Promise(function (resolve) {
      var g = db.transaction('k', 'readonly').objectStore('k').get('key');
      g.onsuccess = function () { etatIdb = g.result ? 'ok' : 'vide'; resolve(g.result || null); db.close(); };
      g.onerror = function () { etatIdb = 'lecture refusée (' + nom(g.error) + ')'; resolve(null); db.close(); };
    });
  }).catch(function (e) { etatIdb = 'ouverture refusée (' + nom(e) + ')'; return null; });
}

function idbClearKey() {
  return idbOpen().then(function (db) {
    return new Promise(function (resolve) {
      var d = db.transaction('k', 'readwrite').objectStore('k').delete('key');
      d.onsuccess = d.onerror = function () { resolve(); db.close(); };
    });
  }).catch(function () {});
}

/* --------------------------------------------------------------------- crypto */

function decrypt(key, buf) {
  var blob = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(0, 12) }, key, blob.slice(12));
}

function importer(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
}

// La page range la clé en octets bruts (`raw`) : Safari n'a longtemps pas su relire ici
// une CryptoKey rangée par la page (WebKit 183167, corrigé en mars 2024 seulement).
// `key` : le format d'avant, une CryptoKey — encore lu, pour ne pas reverrouiller qui l'a.
function cleDepuis(rec) {
  if (!rec) return Promise.resolve(null);
  if (rec.raw) return importer(rec.raw);
  return Promise.resolve(rec.key || null);
}

/* ------------------------------------------------------------------ manifeste */

var site = null;        // { key, man, lc }
var siteAt = 0;
var sitePending = null;
var cleMemoire = null;  // clé remise par l'écran de verrouillage : le secours si IndexedDB est illisible ici
var raison = '';        // pourquoi le site n'est pas servi — renvoyé à l'écran de verrouillage

function indexLower(files) {
  var lc = Object.create(null);
  for (var p in files) lc[p.toLowerCase()] = files[p];
  return lc;
}

function loadSite() {
  return idbGetKey().then(cleDepuis).catch(function (e) {
    etatIdb = 'clé illisible (' + nom(e) + ')';
    return null;
  }).then(function (key) {
    key = key || cleMemoire;
    if (!key) { site = null; raison = 'aucune clé — IndexedDB : ' + etatIdb; return null; }
    return fetch(BASE + MANIFEST, { cache: 'no-store' }).then(function (res) {
      if (!res.ok) throw Object.assign(new Error('manifest ' + res.status), { net: true });
      return res.arrayBuffer();
    }).then(function (buf) {
      return decrypt(key, buf);
    }).then(function (plain) {
      var man = JSON.parse(new TextDecoder().decode(plain));
      site = { key: key, man: man, lc: indexLower(man.f) };
      siteAt = Date.now();
      raison = '';
      return site;
    }).catch(function (err) {
      if (err && err.net) {            // réseau indisponible : on garde l'état courant
        siteAt = Date.now();
        raison = 'réseau (' + err.message + ')';
        return site;
      }
      // déchiffrement impossible → la clé stockée ne correspond plus (mot de passe changé)
      site = null; cleMemoire = null;
      raison = 'manifeste indéchiffrable (' + nom(err) + ')';
      return idbClearKey().then(function () { return null; });
    });
  });
}

function getSite() {
  if (site && Date.now() - siteAt < MANIFEST_TTL) return Promise.resolve(site);
  if (sitePending) return sitePending;
  sitePending = loadSite();
  var done = function () { sitePending = null; };
  sitePending.then(done, done);
  return sitePending;
}

/* ------------------------------------------------- cache mémoire des fichiers */

var mem = new Map();     // id → { buf, at }
var memBytes = 0;
var inflight = new Map();

function remember(id, buf) {
  if (buf.byteLength > MEM_BUDGET) return;
  mem.set(id, { buf: buf, at: Date.now() });
  memBytes += buf.byteLength;
  if (memBytes <= MEM_BUDGET) return;
  var old = Array.from(mem.entries()).sort(function (a, b) { return a[1].at - b[1].at; });
  for (var i = 0; i < old.length && memBytes > MEM_BUDGET; i++) {
    if (old[i][0] === id) continue;
    memBytes -= old[i][1].buf.byteLength;
    mem.delete(old[i][0]);
  }
}

function getFile(s, meta) {
  var hit = mem.get(meta.i);
  if (hit) { hit.at = Date.now(); return Promise.resolve(hit.buf); }
  if (inflight.has(meta.i)) return inflight.get(meta.i);

  var p = fetch(BASE + ENC + meta.i + '.bin').then(function (res) {
    if (!res.ok) throw new Error('enc ' + res.status);
    return res.arrayBuffer();
  }).then(function (buf) {
    return decrypt(s.key, buf);
  }).then(function (plain) {
    remember(meta.i, plain);
    return plain;
  });

  inflight.set(meta.i, p);
  var done = function () { inflight.delete(meta.i); };
  p.then(done, done);
  return p;
}

/* ------------------------------------------------------------------ réponses */

function serve(req, buf, type) {
  var base = { 'Content-Type': type, 'Cache-Control': 'no-store', 'Accept-Ranges': 'bytes' };
  var range = req.headers.get('range');
  var m = range && /^bytes=(\d*)-(\d*)$/.exec(range.trim());
  if (!m) return new Response(buf, { status: 200, headers: base });

  // Safari n'accepte de lire une vidéo que si les requêtes Range reçoivent un 206.
  var size = buf.byteLength, start, end;
  if (m[1] === '') {
    var n = parseInt(m[2], 10);
    if (isNaN(n)) return new Response(buf, { status: 200, headers: base });
    start = Math.max(0, size - n); end = size - 1;
  } else {
    start = parseInt(m[1], 10);
    end = m[2] === '' ? size - 1 : Math.min(parseInt(m[2], 10), size - 1);
  }
  if (isNaN(start) || start > end || start >= size) {
    return new Response('', { status: 416, headers: { 'Content-Range': 'bytes */' + size } });
  }
  var slice = buf.slice(start, end + 1);
  var headers = Object.assign({}, base, {
    'Content-Range': 'bytes ' + start + '-' + end + '/' + size,
    'Content-Length': String(slice.byteLength),
  });
  return new Response(slice, { status: 206, headers: headers });
}

var NOT_INCLUDED = '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1">' +
  '<title>Page non incluse</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;' +
  'font-family:system-ui,-apple-system,sans-serif;background:#f6f9fc;color:#15233a;text-align:center;padding:24px}' +
  'p{max-width:32rem;line-height:1.6;color:#5b6b80}a{display:inline-block;margin-top:20px;padding:12px 20px;border-radius:12px;' +
  'background:#002856;color:#fff;text-decoration:none;font-weight:700}</style></head><body><div>' +
  '<h1>Cette page ne fait pas partie de la présentation</h1>' +
  '<p>Le lien existe dans la maquette mais le document correspondant n’a pas été publié.</p>' +
  '<a href="' + BASE + '">Revenir à la maquette</a></div></body></html>';

function lookup(s, path) {
  return s.man.f[path] || s.lc[path.toLowerCase()] || null;
}

function handle(req, rel) {
  return getSite().then(function (s) {
    if (!s) return fetch(req);        // verrouillé → réseau (donc écran de mot de passe)

    var path = rel;
    if (path === '' || path === 'index.html' || path === '404.html') path = ENTRY;
    else if (path.charAt(path.length - 1) === '/') path += 'index.html';

    var meta = lookup(s, path);
    if (!meta) {
      if (req.mode === 'navigate') {
        return new Response(NOT_INCLUDED, { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
      return new Response('', { status: 404 });
    }

    return getFile(s, meta).then(
      function (buf) { return serve(req, buf, meta.t); },
      function () {
        // .bin absent ou indéchiffrable → manifeste périmé (nouveau déploiement) : on retente une fois
        site = null; siteAt = 0;
        return getSite().then(function (s2) {
          if (!s2) return fetch(req);
          var m2 = lookup(s2, path);
          if (!m2) return new Response('', { status: 404 });
          return getFile(s2, m2).then(function (buf) { return serve(req, buf, m2.t); });
        });
      }
    );
  }).catch(function () { return fetch(req); });
}

// L'écran de verrouillage remet la clé et demande si le site se déchiffre, AVANT de
// recharger la page : il affiche la raison d'un refus au lieu de boucler à l'aveugle.
// La clé reçue reste en mémoire : elle sert si IndexedDB est illisible depuis le worker,
// jusqu'à ce que le navigateur l'arrête (on redemandera alors le mot de passe).
self.addEventListener('message', function (event) {
  var d = event.data || {};
  var port = event.ports && event.ports[0];
  if (!port || d.type !== 'ouvrir') return;
  var travail = (d.raw ? importer(d.raw).then(function (k) { cleMemoire = k; }) : Promise.resolve())
    .then(function () { site = null; siteAt = 0; sitePending = null; return getSite(); })
    .then(function (s) { port.postMessage({ ok: !!s, raison: s ? '' : raison, idb: etatIdb }); })
    .catch(function (err) { port.postMessage({ ok: false, raison: 'ouverture (' + nom(err) + ')', idb: etatIdb }); });
  if (event.waitUntil) event.waitUntil(travail);
});

self.addEventListener('fetch', function (event) {
  var req = event.request;
  if (req.method !== 'GET') return;

  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.indexOf(BASE) !== 0) return;

  var rel = url.pathname.slice(BASE.length);
  try { rel = decodeURIComponent(rel); } catch (e) { /* laissé tel quel */ }
  rel = rel.normalize ? rel.normalize('NFC') : rel;

  // Coquille publique et fichiers chiffrés : servis par le réseau, jamais interceptés.
  if (rel === 'sw.js' || rel === 'robots.txt' || rel.indexOf(ENC) === 0) return;

  event.respondWith(handle(req, rel));
});
