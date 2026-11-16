/* الدليل الحاسم — محرك اللعبة
   البنية: جهاز المضيف هو "الحَكَم" الذي يحمل حالة اللعبة كاملة.
   الأجهزة تتصل عبر خادم MQTT عام. الحالة العامة تُبث للجميع،
   والأسرار (الأدوار والحل) تُرسل لكل لاعب مشفّرة بمفتاح خاص به (ECDH + AES-GCM). */
'use strict';

/* ================= أدوات عامة ================= */
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rnd = n => Math.floor(Math.random() * n);
const shuffle = a => { a = [...a]; for (let i = a.length - 1; i > 0; i--) { const j = rnd(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };
const uid = (n = 10) => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => 'abcdefghijklmnopqrstuvwxyz0123456789'[b % 36]).join('');
const CODE_CH = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const genCode = () => Array.from(crypto.getRandomValues(new Uint8Array(5)), b => CODE_CH[b % CODE_CH.length]).join('');

const COLORS = ['#e0625a', '#e39b4a', '#d9c45a', '#8cc26b', '#4fb39a', '#4aa6d6', '#7d8fe6', '#a77ade', '#d46fb0', '#c19a74', '#a9b6bb', '#ef8fa0'];
const REACTS = ['🤔', '😱', '🤥', '👀', '😂', '👏'];
const BROKERS = ['wss://broker.emqx.io:8084/mqtt', 'wss://broker.hivemq.com:8884/mqtt', 'wss://test.mosquitto.org:8081/mqtt'];
const PFX = 'daleel-hasem/v1/';
const MAX_PLAYERS = 12;
const ROUNDS = 3;

const ROLES = {
  forensic: { n: 'الطبيب الشرعي', team: 'good', d: 'تعرف الحل كاملاً، لكن يُمنع عليك الكلام والإشارة تماماً. ساعد المحققين فقط بوضع رصاصاتك على بطاقات المشهد.' },
  murderer: { n: 'القاتل', team: 'evil', d: 'اخترت أداة الجريمة والدليل الحاسم من بطاقاتك. ضلّل المحققين، وألصق التهمة بغيرك، ولا تنكشف.' },
  accomplice: { n: 'الشريك', team: 'evil', d: 'تعرف القاتل والحل. ساعده على الإفلات بتوجيه الشكوك بعيداً عنه، دون أن تنكشف أنت.' },
  witness: { n: 'الشاهد', team: 'good', d: 'رأيت شخصين يغادران مسرح الجريمة: أحدهما القاتل والآخر شريكه. وجّه التحقيق بذكاء، فإن كُشف القاتل وعرف أنك الشاهد فسيُسكتك ويفوز.' },
  investigator: { n: 'محقق', team: 'good', d: 'حلّل إشارات الطبيب الشرعي واكتشف أداة الجريمة والدليل الحاسم. لديك شارة واحدة فقط للاتهام.' }
};
const GOOD = ['forensic', 'investigator', 'witness'];

/* ================= التخزين ================= */
function parseHash() {
  const h = decodeURIComponent(location.hash.slice(1));
  const m = h.match(/^([A-Za-z0-9]{5})(?:-(\d))?(?:~(\w{1,8}))?$/);
  return m ? { code: m[1].toUpperCase(), b: Math.min(+(m[2] || 0), BROKERS.length - 1), slot: m[3] || '' } : null;
}
const BOOT_HASH = parseHash();
const SLOT = (location.hash.match(/~(\w{1,8})$/) || [])[1] || '';
const NS = 'qd' + (SLOT ? '_' + SLOT : '');
const store = {
  get(k) { try { return JSON.parse(localStorage.getItem(NS + k)); } catch (e) { return null; } },
  set(k, v) { try { localStorage.setItem(NS + k, JSON.stringify(v)); } catch (e) { } },
  del(k) { try { localStorage.removeItem(NS + k); } catch (e) { } }
};
const sess = {
  get(k) { try { return JSON.parse(sessionStorage.getItem(NS + k)); } catch (e) { return null; } },
  set(k, v) { try { sessionStorage.setItem(NS + k, JSON.stringify(v)); } catch (e) { } }
};

/* ================= التشفير ================= */
const HAS_CRYPTO = !!(window.crypto && crypto.subtle);
function b64(buf) { const u = new Uint8Array(buf); let s = ''; for (let i = 0; i < u.length; i += 8192) s += String.fromCharCode.apply(null, u.subarray(i, i + 8192)); return btoa(s); }
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function genKeys() {
  if (!HAS_CRYPTO) return { pub: null, priv: null };
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  return { pub: await crypto.subtle.exportKey('jwk', kp.publicKey), priv: await crypto.subtle.exportKey('jwk', kp.privateKey) };
}
async function derive(privJwk, pubJwk) {
  const priv = await crypto.subtle.importKey('jwk', privJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
  const pub = await crypto.subtle.importKey('jwk', pubJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  return crypto.subtle.deriveKey({ name: 'ECDH', public: pub }, priv, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(key, obj) {
  if (!key) return { p: obj };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { iv: b64(iv), d: b64(ct) };
}
async function unseal(key, env) {
  if (env.p) return env.p;
  if (!key) throw new Error('no key');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv) }, key, unb64(env.d));
  return JSON.parse(new TextDecoder().decode(pt));
}
const samePub = (a, b) => !!a && !!b && a.x === b.x && a.y === b.y;

/* ================= الصوت ================= */
const Snd = {
  ctx: null, on: store.get('_snd') !== false,
  init() {
    if (!this.ctx) { try { this.ctx = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { } }
    if (this.ctx && this.ctx.state === 'suspended') this.ctx.resume();
  },
  tone(f, d = .15, type = 'sine', v = .12, delay = 0) {
    if (!this.on || !this.ctx) return;
    const t = this.ctx.currentTime + delay, o = this.ctx.createOscillator(), g = this.ctx.createGain();
    o.type = type; o.frequency.setValueAtTime(f, t);
    g.gain.setValueAtTime(.0001, t); g.gain.exponentialRampToValueAtTime(v, t + .02); g.gain.exponentialRampToValueAtTime(.0001, t + d);
    o.connect(g).connect(this.ctx.destination); o.start(t); o.stop(t + d + .05);
  },
  play(n) {
    switch (n) {
      case 'turn': this.tone(660, .12, 'triangle', .16); this.tone(880, .2, 'triangle', .16, .14); break;
      case 'drum': for (let i = 0; i < 10; i++) this.tone(62 + i * 5, .14, 'sine', .32, i * .2); break;
      case 'ok': [523, 659, 784, 1046].forEach((f, i) => this.tone(f, .6, 'triangle', .13, i * .09)); break;
      case 'bad': this.tone(150, .6, 'sawtooth', .07); this.tone(112, .8, 'sawtooth', .07, .12); break;
      case 'night': this.tone(98, 1.6, 'sine', .14); this.tone(147, 1.6, 'sine', .07, .15); break;
      case 'chime': [784, 988, 1175].forEach((f, i) => this.tone(f, .4, 'sine', .1, i * .11)); break;
      case 'tick': this.tone(1250, .05, 'square', .035); break;
      case 'pop': this.tone(520, .08, 'sine', .08); break;
    }
  }
};
function vibrate(ms) {
  try {
    if (navigator.userActivation && !navigator.userActivation.hasBeenActive) return;
    navigator.vibrate && navigator.vibrate(ms);
  } catch (e) { }
}

/* ================= حالة الواجهة ================= */
const S = {
  room: null, me: null, pub: null, priv: null, offset: 0, err: null, pendingJoin: null,
  form: { name: '', color: COLORS[rnd(COLORS.length)], code: '' },
  ui: { modal: null }, g: {}, evLast: null, turnKey: undefined, notes: {}, gid: null
};
function resetGameUI() {
  S.g = { revealed: false, seenRole: false, night: { m: null, c: null, done: false }, fx: { cause: null, loc: null, sc: {} }, sw: { remove: null, tile: null, opt: null }, acc: null, hunt: null, helper: true };
}
resetGameUI();

/* ================= الشبكة ================= */
const Net = { c: null, code: null, b: 0, isHost: false, hostPub: null, key: null, hostOn: false, pendingPriv: null, seenHost: false };
const TP = s => PFX + Net.code + '/' + s;

function mqttConnect(b, will) {
  return new Promise((res, rej) => {
    if (!window.mqtt) { rej(new Error('mqtt missing')); return; }
    const c = mqtt.connect(BROKERS[b], { clientId: 'qd_' + uid(12), keepalive: 30, reconnectPeriod: 2500, connectTimeout: 8000, clean: true, will });
    const to = setTimeout(() => { c.end(true); rej(new Error('timeout')); }, 9000);
    c.once('connect', () => { clearTimeout(to); res(c); });
  });
}

/* ================= المضيف (الحَكَم) ================= */
let H = null;           // حالة اللعبة الكاملة — توجد فقط على جهاز المضيف
const HK = {};          // مفاتيح التشفير المشتقة لكل لاعب
const privCache = {};

function newHostState(code, b, pid, keys) {
  return {
    code, b, hostId: pid, keys, v: 0, phase: 'lobby',
    settings: { timer: 60, accomplice: true, witness: true, helper: true, forensic: 'random' },
    players: [], conn: {}, pubs: {}, spect: {}, kicked: [], scores: {}, game: null, evs: [], evSeq: 0, lastForensic: null
  };
}
function hostKey(pid) {
  if (!HAS_CRYPTO || !H.pubs[pid]) return Promise.resolve(null);
  if (!HK[pid]) HK[pid] = derive(H.keys.priv, H.pubs[pid]).catch(() => null);
  return HK[pid];
}
function pushEv(e) { H.evSeq = (H.evSeq || 0) + 1; H.evs = [...(H.evs || []).slice(-5), { ...e, n: H.evSeq }]; }
const murd = g => Object.keys(g.roles).find(i => g.roles[i] === 'murderer');
const acc = g => Object.keys(g.roles).find(i => g.roles[i] === 'accomplice') || null;
const wit = g => Object.keys(g.roles).find(i => g.roles[i] === 'witness') || null;

function publicView() {
  const g = H.game, ph = H.phase;
  const pv = {
    app: 'qd1', code: H.code, v: H.v, now: Date.now(), phase: ph, hostId: H.hostId, settings: H.settings,
    players: H.players.map(p => ({ id: p.id, name: p.name, color: p.color, on: p.id === H.hostId || H.conn[p.id] !== false })),
    scores: H.scores, evs: H.evs, kicked: H.kicked
  };
  if (g) {
    const reveal = ph === 'end', open = ph === 'hunt' || reveal;
    pv.g = {
      id: g.id, forensic: g.forensic, hands: g.hands, badges: g.badges, board: g.board, round: g.round, talk: g.talk,
      log: g.log, counts: g.counts, ready: Object.keys(g.ready), picked: !!g.sol, result: g.result,
      hero: open ? g.hero : null, evil: open ? { m: murd(g), a: acc(g) } : null,
      roles: reveal ? g.roles : null, sol: reveal ? g.sol : null
    };
  }
  return pv;
}
function privateView(pid) {
  const g = H.game, base = { v: H.v, gid: g ? g.id : null };
  if (!g) return base;
  const r = g.roles[pid];
  if (!r) return { ...base, role: 'spectator' };
  const o = { ...base, role: r }, M = murd(g), A = acc(g);
  if (r === 'murderer') { o.sol = g.sol; o.ally = A; if (H.phase === 'hunt') o.suggest = g.hunt && g.hunt.suggest; }
  if (r === 'accomplice') { o.sol = g.sol; o.ally = M; if (H.phase === 'hunt') o.suggest = g.hunt && g.hunt.suggest; }
  if (r === 'forensic') { o.sol = g.sol; o.offer = g.offer; o.swapOffer = g.swapOffer; o.ally = A; o.wit = wit(g); }
  if (r === 'witness') o.seen = g.wSeen;
  return o;
}
async function pubPriv(pid, obj) {
  const k = await hostKey(pid);
  if (HAS_CRYPTO && !k) return;
  const env = await seal(k, obj);
  Net.c && Net.c.publish(TP('p/' + pid), JSON.stringify(env), { qos: 1, retain: true });
}
function hostCommit(force) {
  H.v++;
  store.set('_host_' + H.code, H);
  const pv = publicView();
  if (Net.c) Net.c.publish(TP('state'), JSON.stringify(pv), { qos: 1, retain: true });
  Object.keys(H.pubs).forEach(pid => {
    if (pid === H.hostId) return;
    const pr = privateView(pid), key = JSON.stringify({ ...pr, v: 0 });
    if (force === true || force === pid || privCache[pid] !== key) { privCache[pid] = key; pubPriv(pid, pr); }
  });
  applyPublic(pv);
  applyPrivate(privateView(H.hostId));
  render();
}

async function onHostMsg(topic, buf) {
  if (topic.endsWith('/fx')) { onFx(buf); return; }
  let m; try { m = JSON.parse(buf.toString()); } catch (e) { return; }
  if (!m || typeof m.from !== 'string' || m.from.length > 20) return;
  if (m.hello) { hostHello(m.from, m.hello); return; }
  if (m.bye) { if (H.conn[m.from] !== false) { H.conn[m.from] = false; hostCommit(); } return; }
  if (m.env) {
    const k = await hostKey(m.from);
    let msg; try { msg = await unseal(k, m.env); } catch (e) { return; }
    hostHandle(m.from, msg);
  }
}
function hostHello(pid, h) {
  if (!h || typeof h !== 'object') return;
  if (HAS_CRYPTO) {
    if (!h.pub || typeof h.pub.x !== 'string') return;
    if (H.pubs[pid] && !samePub(H.pubs[pid], h.pub)) return; // انتحال هوية
  }
  H.pubs[pid] = h.pub || {};
  H.conn[pid] = true;
  const name = String(h.name || '').trim().slice(0, 16) || 'محقق';
  const color = COLORS.includes(h.color) ? h.color : COLORS[0];
  const p = H.players.find(x => x.id === pid);
  if (p) { if (H.phase === 'lobby') { p.name = name; p.color = color; } }
  else if (H.phase === 'lobby' && H.players.length < MAX_PLAYERS && !H.kicked.includes(pid)) H.players.push({ id: pid, name, color });
  else H.spect[pid] = name;
  hostCommit(pid);
}

function hostHandle(pid, msg) {
  if (!msg || typeof msg.type !== 'string') return;
  const g = H.game, isHost = pid === H.hostId, ph = H.phase;
  switch (msg.type) {
    case 'settings': {
      if (!isHost || ph !== 'lobby') return;
      const s = msg.s || {}, st = H.settings;
      if ([0, 30, 45, 60, 90, 120].includes(+s.timer)) st.timer = +s.timer;
      ['accomplice', 'witness', 'helper'].forEach(k => { if (typeof s[k] === 'boolean') st[k] = s[k]; });
      if (typeof s.forensic === 'string' && (s.forensic === 'random' || s.forensic === 'rotate' || H.players.some(p => p.id === s.forensic))) st.forensic = s.forensic;
      break;
    }
    case 'kick': {
      if (!isHost || ph !== 'lobby' || msg.pid === H.hostId) return;
      H.players = H.players.filter(p => p.id !== msg.pid);
      if (!H.kicked.includes(msg.pid)) H.kicked.push(msg.pid);
      break;
    }
    case 'start': if (!isHost || ph !== 'lobby' || H.players.length < 4) return; startGame(); break;
    case 'ready': {
      if (ph !== 'roles' || !g.roles[pid]) return;
      g.ready[pid] = 1;
      if (H.players.every(p => g.ready[p.id] || (p.id !== H.hostId && H.conn[p.id] === false))) toNight();
      break;
    }
    case 'forceNight': if (!isHost || ph !== 'roles') return; toNight(); break;
    case 'pick': {
      if (ph !== 'night' || g.roles[pid] !== 'murderer') return;
      const h = g.hands[pid];
      if (!h.m.includes(msg.m) || !h.c.includes(msg.c)) return;
      g.sol = { pid, m: msg.m, c: msg.c };
      g.offer = shuffle(SCENES.map(t => t.id)).slice(0, 6);
      H.phase = 'setup';
      pushEv({ type: 'dawn' });
      break;
    }
    case 'setup': {
      if (ph !== 'setup' || g.roles[pid] !== 'forensic') return;
      const b = msg.b || {};
      const okOpt = x => Number.isInteger(x) && x >= 0 && x < 6;
      if (!okOpt(b.cause) || !b.loc || !LOCS.some(l => l.id === b.loc.tile) || !okOpt(b.loc.opt)) return;
      if (!Array.isArray(b.scenes) || b.scenes.length !== 4) return;
      const seen = new Set();
      for (const s of b.scenes) { if (!s || !g.offer.includes(s.tile) || seen.has(s.tile) || !okOpt(s.opt)) return; seen.add(s.tile); }
      g.board = { cause: { tile: 'C', opt: b.cause }, loc: { tile: b.loc.tile, opt: b.loc.opt }, scenes: b.scenes.map(s => ({ tile: s.tile, opt: s.opt, r: 1 })) };
      g.used = [...g.offer]; g.offer = []; g.round = 1;
      startTalk();
      pushEv({ type: 'board' });
      break;
    }
    case 'next': {
      if (ph !== 'talk' || msg.idx !== g.talk.idx) return;
      const sp = g.talk.order[g.talk.idx];
      if (pid !== sp && g.roles[pid] !== 'forensic' && !isHost) return;
      advanceTalk();
      break;
    }
    case 'accuse': {
      if (!['talk', 'swap'].includes(ph) || !g.badges[pid]) return;
      const tg = msg.target, h = g.hands[tg];
      if (tg === pid || !h || !h.m.includes(msg.m) || !h.c.includes(msg.c)) return;
      g.badges[pid] = false;
      const ok = tg === g.sol.pid && msg.m === g.sol.m && msg.c === g.sol.c;
      g.log.push({ t: 'accuse', by: pid, target: tg, m: msg.m, c: msg.c, ok, r: g.round });
      pushEv({ type: 'accuse', by: pid, target: tg, m: msg.m, c: msg.c, ok });
      if (ok) {
        g.hero = pid;
        if (g.counts.wit) { H.phase = 'hunt'; g.hunt = { suggest: null }; }
        else finish('good', 'solved');
      } else {
        const left = Object.keys(g.badges).filter(i => g.badges[i] && (g.roles[i] === 'investigator' || g.roles[i] === 'witness'));
        if (!left.length) finish('evil', 'nobadges');
      }
      break;
    }
    case 'swap': {
      if (ph !== 'swap' || g.roles[pid] !== 'forensic') return;
      const i = msg.remove, opt = msg.opt;
      if (!Number.isInteger(i) || i < 0 || i > 3 || !g.swapOffer.includes(msg.tile) || !Number.isInteger(opt) || opt < 0 || opt > 5) return;
      g.board.scenes[i] = { tile: msg.tile, opt, r: g.round + 1 };
      g.used.push(...g.swapOffer); g.swapOffer = [];
      g.round++;
      g.log.push({ t: 'swap', r: g.round, tile: msg.tile });
      startTalk();
      pushEv({ type: 'swap', r: g.round });
      break;
    }
    case 'suggest': if (ph !== 'hunt' || g.roles[pid] !== 'accomplice' || !g.hands[msg.target]) return; g.hunt.suggest = msg.target; break;
    case 'hunt': {
      if (ph !== 'hunt' || g.roles[pid] !== 'murderer') return;
      const tg = msg.target, r = g.roles[tg];
      if (!r || ['forensic', 'murderer', 'accomplice'].includes(r)) return;
      const hit = r === 'witness';
      pushEv({ type: 'hunt', target: tg, hit });
      finish(hit ? 'evil' : 'good', hit ? 'witness' : 'missed', { huntTarget: tg });
      break;
    }
    case 'newgame': case 'abort': if (!isHost || !g) return; H.phase = 'lobby'; H.game = null; break;
    default: return;
  }
  hostCommit();
}

function startGame() {
  const ids = H.players.map(p => p.id), n = ids.length, fm = H.settings.forensic;
  let fid;
  if (fm === 'rotate' && H.lastForensic && ids.includes(H.lastForensic)) fid = ids[(ids.indexOf(H.lastForensic) + 1) % n];
  else if (fm !== 'random' && fm !== 'rotate' && ids.includes(fm)) fid = fm;
  else fid = ids[rnd(n)];
  H.lastForensic = fid;
  const others = shuffle(ids.filter(i => i !== fid));
  const useAcc = n >= 6 && H.settings.accomplice, useWit = useAcc && H.settings.witness;
  const roles = { [fid]: 'forensic' };
  roles[others[0]] = 'murderer';
  let k = 1;
  if (useAcc) roles[others[k++]] = 'accomplice';
  if (useWit) roles[others[k++]] = 'witness';
  others.slice(k).forEach(i => { roles[i] = 'investigator'; });
  const md = shuffle(MEANS.map(c => c.id)), cd = shuffle(CLUES.map(c => c.id));
  const hands = {}, badges = {};
  ids.filter(i => i !== fid).forEach(i => { hands[i] = { m: md.splice(0, 4), c: cd.splice(0, 4) }; badges[i] = true; });
  H.game = {
    id: uid(6), forensic: fid, roles, hands, badges, sol: null, board: null, offer: [], swapOffer: [], used: [],
    round: 0, talk: null, log: [], ready: {}, result: null, hunt: null, hero: null,
    wSeen: useWit ? shuffle([others[0], others[1]]) : null,
    counts: { n, acc: useAcc, wit: useWit }, startBase: rnd(n - 1)
  };
  H.phase = 'roles';
  pushEv({ type: 'start' });
}
function toNight() { H.phase = 'night'; pushEv({ type: 'night' }); }
function speakerOk(pid) { return pid === H.hostId || H.conn[pid] !== false; }
function startTalk() {
  const g = H.game;
  const base = H.players.map(p => p.id).filter(i => g.hands[i]);
  const s = (g.startBase + g.round - 1) % base.length;
  const order = [...base.slice(s), ...base.slice(0, s)];
  g.talk = { order, idx: -1, endsAt: null };
  H.phase = 'talk';
  advanceTalk(true);
}
function advanceTalk() {
  const g = H.game, t = g.talk;
  do { t.idx++; } while (t.idx < t.order.length && !speakerOk(t.order[t.idx]));
  if (t.idx >= t.order.length) {
    if (g.round < ROUNDS) {
      H.phase = 'swap';
      const pool = SCENES.map(x => x.id).filter(id => !g.used.includes(id) && !g.board.scenes.some(s => s.tile === id));
      g.swapOffer = shuffle(pool).slice(0, 3);
      g.talk = null;
      pushEv({ type: 'roundEnd', r: g.round });
    } else finish('evil', 'time');
    return;
  }
  t.endsAt = H.settings.timer ? Date.now() + H.settings.timer * 1000 : null;
}
function finish(winner, reason, extra = {}) {
  const g = H.game;
  g.result = { winner, reason, ...extra };
  Object.keys(g.roles).forEach(i => {
    const good = GOOD.includes(g.roles[i]);
    if ((winner === 'good') === good) H.scores[i] = (H.scores[i] || 0) + 1;
  });
  if (winner === 'good' && g.hero && GOOD.includes(g.roles[g.hero])) H.scores[g.hero] = (H.scores[g.hero] || 0) + 1;
  g.talk = null;
  H.phase = 'end';
  pushEv({ type: 'end', winner });
}

function startHostNet(c) {
  Net.c = c; Net.isHost = true; Net.hostOn = true; Net.seenHost = true;
  const announce = () => {
    c.publish(TP('host'), JSON.stringify({ on: true, pub: H.keys.pub }), { qos: 1, retain: true });
    hostCommit(true);
  };
  c.subscribe([TP('c2h'), TP('fx')], { qos: 1 });
  c.on('message', onHostMsg);
  c.on('connect', announce);
  c.on('offline', () => toast('انقطع الاتصال… نحاول إعادة الاتصال'));
  Object.keys(H.pubs).forEach(pid => hostKey(pid));
  announce();
}

/* ================= العميل ================= */
async function getIdentity(code) {
  let id = store.get('_id_' + code);
  if (!id || !id.pid) { id = { pid: uid(10), keys: await genKeys() }; store.set('_id_' + code, id); }
  return id;
}
function saveProfile() { store.set('_profile', { name: S.form.name.trim(), color: S.form.color }); }
function setHash(code, b) { history.replaceState(null, '', '#' + code + '-' + b + (SLOT ? '~' + SLOT : '')); }
function inviteLink() { return location.origin + location.pathname + '#' + Net.code + '-' + Net.b; }

async function createRoom() {
  if (!S.form.name.trim()) { toast('اكتب اسمك أولاً'); $('#nm') && $('#nm').focus(); return; }
  saveProfile();
  S.status = 'creating'; S.room = { code: '…' }; render();
  const code = genCode();
  const id = await getIdentity(code);
  for (let b = 0; b < BROKERS.length; b++) {
    try {
      Net.code = code; Net.b = b;
      const c = await mqttConnect(b, { topic: PFX + code + '/host', payload: JSON.stringify({ on: false, pub: id.keys.pub }), qos: 1, retain: true });
      H = newHostState(code, b, id.pid, id.keys);
      H.players.push({ id: id.pid, name: S.form.name.trim().slice(0, 16), color: S.form.color });
      H.conn[id.pid] = true; H.pubs[id.pid] = id.keys.pub || {};
      S.me = { pid: id.pid }; S.room = { code, b };
      setHash(code, b);
      startHostNet(c);
      return;
    } catch (e) { /* جرّب الخادم التالي */ }
  }
  S.room = null;
  S.err = 'net';
  render();
}
async function resumeHost(hs, id) {
  H = hs; Net.code = hs.code; Net.b = hs.b;
  S.me = { pid: id.pid }; S.room = { code: hs.code, b: hs.b };
  Object.keys(H.conn).forEach(k => { if (k !== H.hostId) H.conn[k] = false; });
  render();
  try {
    const c = await mqttConnect(hs.b, { topic: PFX + hs.code + '/host', payload: JSON.stringify({ on: false, pub: id.keys.pub }), qos: 1, retain: true });
    startHostNet(c);
  } catch (e) { S.err = 'net'; render(); }
}
async function enterRoom(code, b) {
  saveProfile();
  Net.code = code; Net.b = b; Net.isHost = false;
  const id = await getIdentity(code);
  S.me = { pid: id.pid, keys: id.keys };
  S.room = { code, b }; S.pub = null; S.priv = null; S.err = null;
  setHash(code, b);
  render();
  let c;
  try {
    c = await mqttConnect(b, { topic: PFX + code + '/c2h', payload: JSON.stringify({ from: id.pid, bye: 1 }), qos: 1, retain: false });
  } catch (e) { S.err = 'net'; render(); return; }
  Net.c = c;
  c.subscribe([TP('state'), TP('host'), TP('p/' + id.pid), TP('fx')], { qos: 1 });
  c.on('message', onClientMsg);
  c.on('connect', () => sendHello());
  c.on('offline', () => { toast('انقطع الاتصال… نحاول إعادة الاتصال'); });
  setTimeout(() => { if (!Net.seenHost && S.room && S.room.code === code) { S.err = 'notfound'; render(); } }, 9000);
}
function sendHello() {
  if (!Net.c || Net.isHost || !Net.seenHost) return;
  const p = store.get('_profile') || {};
  Net.c.publish(TP('c2h'), JSON.stringify({ from: S.me.pid, hello: { pub: S.me.keys.pub, name: p.name || S.form.name || 'محقق', color: p.color || S.form.color } }), { qos: 1 });
}
async function onClientMsg(topic, buf) {
  if (topic.endsWith('/fx')) { onFx(buf); return; }
  let m; try { m = JSON.parse(buf.toString()); } catch (e) { return; }
  if (!m) return;
  if (topic.endsWith('/host')) {
    Net.seenHost = true;
    if (S.err === 'notfound') S.err = null;
    if (m.pub && HAS_CRYPTO && !samePub(Net.hostPub, m.pub)) {
      Net.hostPub = m.pub;
      try { Net.key = await derive(S.me.keys.priv, m.pub); } catch (e) { Net.key = null; }
      if (Net.pendingPriv) onPrivEnv(Net.pendingPriv);
    }
    const was = Net.hostOn;
    Net.hostOn = !!m.on;
    if (m.on) sendHello();
    if (was !== Net.hostOn) render();
    return;
  }
  if (topic.endsWith('/state')) {
    if (m.app !== 'qd1') return;
    if (S.pub && S.pub.code === m.code && m.v < S.pub.v) return;
    applyPublic(m);
    render();
    return;
  }
  if (topic.includes('/p/')) onPrivEnv(m);
}
async function onPrivEnv(env) {
  Net.pendingPriv = env;
  if (HAS_CRYPTO && !Net.key) return;
  let pr; try { pr = await unseal(Net.key, env); } catch (e) { return; }
  if (S.priv && pr.gid === S.priv.gid && pr.v < S.priv.v) return;
  if (S.pub && pr.gid !== (S.pub.g ? S.pub.g.id : null) && pr.v < S.pub.v) return; // رسالة قديمة وصلت متأخرة
  applyPrivate(pr);
  render();
}

function applyPublic(pv) {
  const prev = S.pub;
  if (!Net.isHost) S.offset = pv.now - Date.now();
  S.pub = pv;
  const gid = pv.g ? pv.g.id : null;
  // لا نخلط دوراً سرياً من قضية سابقة مع قضية جديدة
  if (S.priv && S.priv.gid !== gid && (S.priv.v || 0) < pv.v) S.priv = null;
  if (gid !== S.gid) {
    S.gid = gid; resetGameUI();
    S.g.helper = pv.settings.helper;
    S.notes = (gid && store.get('_notes_' + pv.code + '_' + gid)) || {};
    if (S.ui.modal === 'accuse' || S.ui.modal === 'role') S.ui.modal = null;
  }
  if (pv.phase !== (prev && prev.phase)) {
    if (pv.phase === 'swap') S.g.sw = { remove: null, tile: null, opt: null };
    if (pv.phase !== 'talk' && pv.phase !== 'swap' && S.ui.modal === 'accuse') S.ui.modal = null;
  }
  if (pv.phase === 'talk' && pv.g.talk) {
    const k = pv.g.round + ':' + pv.g.talk.idx, was = S.turnKey;
    S.turnKey = k;
    if (k !== was && was !== undefined && pv.g.talk.order[pv.g.talk.idx] === S.me.pid) {
      Snd.play('turn'); vibrate([120, 60, 120]); toast('دورك في الكلام الآن');
    }
  } else S.turnKey = null;
  processEvs(pv);
}
function applyPrivate(pr) {
  const prev = S.priv;
  S.priv = pr;
  if (prev && prev.gid === pr.gid && !prev.sol && pr.sol && ['accomplice', 'forensic'].includes(pr.role)) {
    toast('وصلتك معلومات جديدة في بطاقتك السرية');
  }
}

async function send(msg) {
  if (Net.isHost) { hostHandle(H.hostId, msg); return; }
  if (!Net.c || !Net.c.connected) { toast('لا يوجد اتصال الآن، حاول بعد لحظات'); return; }
  if (!Net.hostOn) { toast('المضيف غير متصل حالياً'); return; }
  const env = await seal(Net.key, msg);
  Net.c.publish(TP('c2h'), JSON.stringify({ from: S.me.pid, env }), { qos: 1 });
}

/* ================= التفاعلات السريعة ================= */
let lastReact = 0;
function react(e) {
  if (Date.now() - lastReact < 700 || !Net.c) return;
  lastReact = Date.now();
  const me = P(S.me.pid);
  const msg = { from: S.me.pid, e, n: me ? me.name : '' };
  Net.c.publish(TP('fx'), JSON.stringify(msg), { qos: 0 });
  showReaction(msg);
}
function onFx(buf) {
  let m; try { m = JSON.parse(buf.toString()); } catch (e) { return; }
  if (!m || m.from === S.me.pid || !REACTS.includes(m.e)) return;
  showReaction(m);
}
function showReaction(m) {
  const el = document.createElement('div');
  el.className = 'rx';
  el.style.setProperty('--x', (10 + rnd(75)) + '%');
  el.innerHTML = `<span>${m.e}</span><small>${esc(String(m.n || '').slice(0, 16))}</small>`;
  $('#fx').appendChild(el);
  setTimeout(() => el.remove(), 2700);
}

/* ================= أحداث المسرح (الرسوم الدرامية) ================= */
const evQ = []; let evBusy = false, stageDone = null;
function processEvs(pv) {
  const evs = pv.evs || [], key = '_ev_' + pv.code;
  if (S.evLast == null) {
    const saved = sess.get(key);
    S.evLast = saved != null ? saved : (evs.length ? evs[evs.length - 1].n : 0);
  }
  for (const e of evs) if (e.n > S.evLast) { S.evLast = e.n; evQ.push(e); }
  sess.set(key, S.evLast);
  runEvQ();
}
async function runEvQ() {
  if (evBusy) return;
  evBusy = true;
  while (evQ.length) { try { await playEv(evQ.shift()); } catch (e) { } }
  evBusy = false;
}
function stage(html, ms, after) {
  return new Promise(res => {
    const st = $('#stage');
    st.innerHTML = `<div class="stage">${html}<p class="skip">اضغط للمتابعة</p></div>`;
    st.hidden = false;
    const el = st.firstElementChild;
    requestAnimationFrame(() => requestAnimationFrame(() => el.classList.add('in')));
    const timers = [];
    if (after) timers.push(setTimeout(() => after(el), after.at));
    const done = () => { timers.forEach(clearTimeout); st.hidden = true; st.innerHTML = ''; stageDone = null; res(); };
    stageDone = () => { if (after && !el.classList.contains('verdict')) { after(el); timers.forEach(clearTimeout); timers.length = 0; timers.push(setTimeout(done, 1800)); } else done(); };
    timers.push(setTimeout(done, ms));
  });
}
function playEv(e) {
  switch (e.type) {
    case 'start': Snd.play('chime'); return stage(`<p class="eyebrow">قضية جديدة</p><h2>وقعت جريمة</h2><p>اكشف دورك بسرية، ولا تدع أحداً يرى شاشتك.</p>`, 2200);
    case 'night': Snd.play('night'); vibrate(80); return stage(`<div class="moon"></div><h2>حلّ الليل</h2><p>القاتل يختار أداته… والجميع يتظاهر بالاختيار.</p>`, 2400);
    case 'dawn': Snd.play('pop'); return stage(`<h2>طلع الصباح</h2><p>عُثر على الجثة. الطبيب الشرعي يفحص مسرح الجريمة الآن.</p>`, 2200);
    case 'board': Snd.play('chime'); return stage(`<p class="eyebrow">تقرير الطب الشرعي</p><h2>ظهرت الإشارات</h2><p>ادرسوا بطاقات المشهد جيداً. الجولة الأولى تبدأ.</p>`, 2400);
    case 'roundEnd': Snd.play('pop'); return stage(`<h2>انتهت الجولة ${e.r}</h2><p>الطبيب الشرعي سيستبدل بطاقة مشهد بإشارة أوضح.</p>`, 2000);
    case 'swap': Snd.play('chime'); return stage(`<p class="eyebrow">الجولة ${e.r} من ${ROUNDS}</p><h2>إشارة جديدة</h2><p>بطاقة المشهد الجديدة معلّمة باللون الأحمر.</p>`, 2200);
    case 'accuse': {
      Snd.play('drum'); vibrate(200);
      const by = P(e.by), tg = P(e.target);
      const after = el => { el.classList.add('verdict'); Snd.play(e.ok ? 'ok' : 'bad'); vibrate(e.ok ? [80, 40, 80] : 300); };
      after.at = 2300;
      return stage(`<p class="eyebrow">اتهام رسمي</p><h2>أتّهم!</h2>
        <div class="who-line">${by ? avatar(by) : ''}<b>${nm(e.by)}</b><span class="arrow">←</span><b>${nm(e.target)}</b>${tg ? avatar(tg) : ''}</div>
        <div class="solline">${cardMini(e.m, 'm')}${cardMini(e.c, 'c')}</div>
        <div class="suspense"><i></i><i></i><i></i></div>
        <div class="stamp ${e.ok ? 'ok' : 'bad'}">${e.ok ? 'صحيح' : 'خطأ'}</div>
        <p class="after">${e.ok ? 'كُشف الحل!' : 'سقطت شارة ' + nm(e.by) + '. يستمر التحقيق.'}</p>`, 5200, after);
    }
    case 'hunt': {
      Snd.play('drum');
      const after = el => { el.classList.add('verdict'); Snd.play(e.hit ? 'bad' : 'ok'); };
      after.at = 2300;
      return stage(`<p class="eyebrow">الفرصة الأخيرة للقاتل</p><h2>من الشاهد؟</h2><p>القاتل يشير إلى <b>${nm(e.target)}</b></p>
        <div class="suspense"><i></i><i></i><i></i></div>
        <div class="stamp ${e.hit ? 'bad' : 'ok'}">${e.hit ? 'أُسكت الشاهد' : 'نجا الشاهد'}</div>`, 5000, after);
    }
    case 'end': Snd.play(e.winner === 'good' ? 'ok' : 'bad'); return stage(`<h2>${e.winner === 'good' ? 'انتصرت العدالة' : 'أفلت القاتل'}</h2><p>انظروا كيف ربط الطبيب الشرعي الإشارات بالحل.</p>`, 2600);
  }
  return Promise.resolve();
}

/* ================= أدوات العرض ================= */
const P = id => S.pub && S.pub.players.find(p => p.id === id);
const nm = id => { const p = P(id); return esc(p ? p.name : (H && H.spect[id]) || 'لاعب غادر'); };
const avatar = (p, cls = '') => `<span class="av ${cls}" style="--c:${p.color}" aria-hidden="true">${esc([...String(p.name).trim()][0] || '؟')}</span>`;
const cardMini = (id, k) => `<span class="card ${k} mini">${esc(CARD[id] ? CARD[id].n : '')}</span>`;
const myRole = () => (S.priv && S.pub && S.pub.g && S.priv.gid === S.pub.g.id) ? S.priv.role : null;
const helperOn = () => S.pub.settings.helper && S.g.helper && myRole() === 'forensic' && S.priv.sol;
const ICON = {
  snd: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 9v6h4l5 4V5L8 9H4z"/><path d="M16 9a4 4 0 0 1 0 6M18.5 6.5a8 8 0 0 1 0 11"/></svg>',
  mute: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 9v6h4l5 4V5L8 9H4z"/><path d="M17 9l5 5M22 9l-5 5"/></svg>',
  menu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>',
  eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  badge: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l2.6 5.6 6.1.7-4.5 4.2 1.2 6L12 15.6 6.6 18.5l1.2-6L3.3 8.3l6.1-.7z"/></svg>'
};

/* باركود رابط الدعوة (يُرسم SVG محلياً، ويختفي بهدوء إن لم تُحمّل المكتبة) */
const qrCache = {};
function qrSVG(text) {
  if (!window.qrcode || !text) return '';
  if (qrCache[text]) return qrCache[text];
  try {
    const q = qrcode(0, 'M'); q.addData(text); q.make();
    const n = q.getModuleCount(); let d = '';
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) d += `M${c} ${r}h1v1h-1z`;
    return (qrCache[text] = `<svg viewBox="-3 -3 ${n + 6} ${n + 6}" shape-rendering="crispEdges" role="img" aria-label="باركود رابط الدعوة"><rect x="-3" y="-3" width="${n + 6}" height="${n + 6}" fill="#fff"/><path d="${d}" fill="#14100a"/></svg>`);
  } catch (e) { return ''; }
}

function toast(t) {
  const el = document.createElement('div');
  el.className = 'toast'; el.textContent = t;
  $('#toast').appendChild(el);
  setTimeout(() => el.remove(), 2800);
}

function tileHTML(id, opt, o = {}) {
  const t = TILE[id]; if (!t) return '';
  const sol = o.hl ? S.priv.sol : null;
  const mT = sol ? CARD[sol.m].tags : null, cT = sol ? CARD[sol.c].tags : null;
  const kl = t.kind === 'cause' ? 'البطاقة الثابتة' : t.kind === 'loc' ? 'مكان الجريمة' : 'بطاقة مشهد';
  const rows = t.o.map((x, i) => {
    const on = i === opt;
    const dots = sol ? `${x.tags.some(g => mT.includes(g)) ? '<b class="dm" title="يرتبط بأداة الجريمة">أ</b>' : ''}${x.tags.some(g => cT.includes(g)) ? '<b class="dc" title="يرتبط بالدليل الحاسم">د</b>' : ''}` : '';
    const inner = `${on ? '<i class="bullet" aria-hidden="true"></i>' : '<i class="pip" aria-hidden="true"></i>'}<span class="ot">${esc(x.n)}</span>${dots ? `<span class="hl">${dots}</span>` : ''}`;
    return o.pick
      ? `<button type="button" class="opt ${on ? 'on' : ''}" data-act="${o.pick}" data-tile="${id}" data-opt="${i}" aria-pressed="${on}">${inner}</button>`
      : `<div class="opt ${on ? 'on' : ''}">${inner}${on ? '<span hidden>(الاختيار)</span>' : ''}</div>`;
  }).join('');
  return `<article class="tile k-${t.kind} ${o.dim ? 'dim' : ''} ${o.fresh ? 'fresh' : ''}"><header><span class="tk">${kl}</span><h3>${esc(t.title)}</h3>${o.fresh ? '<span class="new">جديدة</span>' : ''}</header><div class="opts">${rows}</div></article>`;
}

function topbar() {
  const pv = S.pub, g = pv && pv.g;
  const showRounds = g && pv.phase !== 'lobby' && g.round > 0;
  return `<header class="top"><div class="top-in wrap">
    <span class="mark">الدليل الحاسم</span>
    ${pv ? `<button class="codechip" data-act="copy" title="انسخ رابط الدعوة" dir="ltr">${pv.code}</button>` : ''}
    ${showRounds ? `<span class="rounds" title="الجولة ${g.round} من ${ROUNDS}">${[1, 2, 3].map(i => `<i class="${i <= g.round ? 'on' : ''}"></i>`).join('')}</span>` : ''}
    <span class="sp"></span>
    ${pv && !Net.isHost && !Net.hostOn ? '<span class="warn">المضيف غير متصل</span>' : ''}
    <button class="icon" data-act="snd" aria-label="${Snd.on ? 'كتم الصوت' : 'تشغيل الصوت'}">${Snd.on ? ICON.snd : ICON.mute}</button>
    <button class="icon" data-act="menu" aria-label="القائمة">${ICON.menu}</button>
  </div></header>`;
}

/* ---------- الصفحة الرئيسية ---------- */
function viewHome() {
  const f = S.form, pre = S.pendingJoin;
  return `<div class="home wrap">
    <div class="hero">
      <p class="case">ملف القضية · سرّي للغاية</p>
      <h1 class="logo">الدليل الحاسم</h1>
      <p class="tag">جريمة واحدة، قاتل يجلس بينكم، وطبيب شرعي لا يحق له الكلام.</p>
      <p class="meta">من ٤ إلى ١٢ لاعباً · قرابة ٢٠ دقيقة · كل لاعب من جواله</p>
      <div class="evidence" aria-hidden="true">
        <svg viewBox="0 0 520 150" preserveAspectRatio="none"><path d="M88 52 C 170 110, 220 20, 262 20 S 380 90, 440 40" fill="none" stroke="#b3242d" stroke-width="2" stroke-dasharray="1 0" opacity=".9"/></svg>
        <div class="ev e1"><small>أداة الجريمة</small><b>فنجان مسموم</b></div>
        <div class="ev e2"><small>سبب الوفاة</small><b>تسمّم</b></div>
        <div class="ev e3"><small>الدليل الحاسم</small><b>مسبحة</b></div>
      </div>
    </div>
    <form class="entry" onsubmit="return false">
      <label for="nm">اسمك في التحقيق</label>
      ${pre ? `<p class="eyebrow">دُعيت إلى الغرفة <span dir="ltr">${esc(pre.code)}</span>، اكتب اسمك وادخل</p>` : ''}
      <input id="nm" class="field" maxlength="16" value="${esc(f.name)}" placeholder="مثلاً: أبو فهد" autocomplete="nickname" ${pre ? 'autofocus' : ''}>
      <div class="colors" role="radiogroup" aria-label="اختر لونك">${COLORS.map(c => `<button type="button" class="sw ${c === f.color ? 'on' : ''}" style="--c:${c}" data-act="color" data-c="${c}" role="radio" aria-checked="${c === f.color}" aria-label="لون"></button>`).join('')}</div>
      ${pre ? `
        <button class="btn primary big" type="button" data-act="joinHash">ادخل الغرفة <span dir="ltr">${esc(pre.code)}</span></button>
        <button class="link" type="button" data-act="clearHash">أو افتح قضية جديدة بنفسك</button>` : `
        <button class="btn primary big" type="button" data-act="create">افتح قضية جديدة</button>
        <div class="or">أو ادخل برمز الغرفة</div>
        <div class="joinrow"><input id="code" class="field" maxlength="5" value="${esc(f.code)}" placeholder="رمز من ٥ أحرف" dir="ltr" autocapitalize="characters" autocomplete="off"><button class="btn" type="button" data-act="join">ادخل</button></div>`}
      <button class="link" type="button" data-act="rules">كيف نلعب؟</button>
    </form>
  </div>`;
}

function viewCenter(title, body, spinner, btn) {
  return `${S.pub ? topbar() : ''}<div class="center-msg wrap">${spinner ? '<div class="spinner"></div>' : ''}<h2>${title}</h2><p class="muted">${body}</p>${btn || ''}</div>`;
}

/* ---------- غرفة الانتظار ---------- */
function viewLobby() {
  const pv = S.pub, isHost = Net.isHost, n = pv.players.length, st = pv.settings, me = S.me.pid;
  const inRoom = pv.players.some(p => p.id === me);
  const dis = isHost ? '' : 'disabled';
  const canExtra = n >= 6;
  const fOpts = [['random', 'عشوائي'], ['rotate', 'بالدور بين اللاعبين'], ...pv.players.map(p => [p.id, p.name])];
  const accOn = canExtra && st.accomplice, witOn = accOn && st.witness;
  const invest = Math.max(0, n - 2 - (accOn ? 1 : 0) - (witOn ? 1 : 0));
  const qr = qrSVG(inviteLink());
  return `${topbar()}<main class="lobby wrap">
    <section class="invite ${qr ? 'has-qr' : ''}">
      ${qr ? `<button class="qr" data-act="qrBig" aria-label="تكبير الباركود">${qr}<span>اضغط للتكبير</span></button>` : ''}
      <div class="invite-txt">
        <p class="eyebrow">رمز الغرفة</p>
        <div class="bigcode" dir="ltr">${pv.code}</div>
        <div class="row center"><button class="btn primary" data-act="copy">انسخ رابط الدعوة</button>${navigator.share ? '<button class="btn" data-act="share">مشاركة</button>' : ''}</div>
        <p class="hint">${qr ? 'الأسرع: يوجّه أصحابك كاميرا الجوال نحو الباركود فيدخلون الغرفة فوراً. ومن ليس معكم في المكان أرسل له الرابط في الواتساب.' : 'أرسل الرابط لأصحابك في الواتساب. كل واحد يفتحه من جواله ويكتب اسمه.'}</p>
      </div>
      ${!inRoom ? `<p class="warn">${pv.kicked.includes(me) ? 'أخرجك المضيف من هذه الغرفة.' : 'الغرفة ممتلئة، يمكنك المشاهدة فقط.'}</p>` : ''}
    </section>
    <section class="roster">
      <h2>المحققون في الغرفة <span class="count">${n}/${MAX_PLAYERS}</span></h2>
      <ul>${pv.players.map(p => `<li class="${p.on ? '' : 'off'}">${avatar(p)}<span class="nm">${esc(p.name)}</span>${p.id === pv.hostId ? '<span class="tagc">المضيف</span>' : ''}${p.id === me ? '<span class="tagc you">أنت</span>' : ''}${pv.scores[p.id] ? `<span class="pts">${pv.scores[p.id]} ن</span>` : ''}${isHost && p.id !== pv.hostId ? `<button class="x" data-act="kick" data-pid="${p.id}" aria-label="إخراج ${esc(p.name)}">×</button>` : ''}</li>`).join('')}</ul>
      ${n < 4 ? `<p class="hint">تحتاجون ${4 - n === 1 ? 'لاعباً واحداً إضافياً' : (4 - n) + ' لاعبين إضافيين'} على الأقل للبدء.</p>` : ''}
    </section>
    <section>
      <h2>إعدادات القضية</h2>
      <div class="set">
        <label class="s"><span>الطبيب الشرعي<small>هو مدير اللعبة الصامت</small></span>
          <select id="set-forensic" data-set="forensic" ${dis}>${fOpts.map(([v, l]) => `<option value="${esc(v)}" ${st.forensic === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
        <label class="s"><span>وقت كلام كل لاعب<small>ينتقل الدور تلقائياً عند انتهائه</small></span>
          <select id="set-timer" data-set="timer" ${dis}>${[[30, '30 ثانية'], [45, '45 ثانية'], [60, 'دقيقة'], [90, 'دقيقة ونصف'], [120, 'دقيقتان'], [0, 'بلا مؤقت']].map(([v, l]) => `<option value="${v}" ${st.timer === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <label class="s tog"><span>دور الشريك<small>${canExtra ? 'يعرف القاتل ويساعده' : 'يتاح من ٦ لاعبين'}</small></span>
          <input type="checkbox" id="set-acc" data-set="accomplice" ${st.accomplice ? 'checked' : ''} ${isHost && canExtra ? '' : 'disabled'}></label>
        <label class="s tog"><span>دور الشاهد<small>${canExtra ? 'يتطلب وجود الشريك' : 'يتاح من ٦ لاعبين'}</small></span>
          <input type="checkbox" id="set-wit" data-set="witness" ${st.witness ? 'checked' : ''} ${isHost && canExtra && st.accomplice ? '' : 'disabled'}></label>
        <label class="s tog"><span>مساعد الطبيب الشرعي<small>يوضح له أي الخيارات ترتبط بالحل</small></span>
          <input type="checkbox" id="set-helper" data-set="helper" ${st.helper ? 'checked' : ''} ${dis}></label>
      </div>
      <div class="dist"><span>طبيب شرعي ١</span><span class="evil">قاتل ١</span>${accOn ? '<span class="evil">شريك ١</span>' : ''}${witOn ? '<span>شاهد ١</span>' : ''}<span>محققون ${invest}</span></div>
      ${isHost ? `<button class="btn primary big" data-act="start" ${n < 4 ? 'disabled' : ''}>ابدأ التحقيق</button>` : '<p class="wait">بانتظار المضيف ليبدأ القضية…</p>'}
    </section>
  </main>${modalHTML()}`;
}

/* ---------- شاشة اللعب ---------- */
function viewGame() {
  return `${topbar()}${phaseBar()}<main class="game wrap">${phasePanel()}${boardSection()}${suspectsSection()}${logSection()}</main>${actionBar()}${modalHTML()}`;
}

function phaseBar() {
  const pv = S.pub, g = pv.g, ph = pv.phase, me = S.me.pid;
  let main = '', side = '', extra = '';
  switch (ph) {
    case 'roles': main = 'اكشف دورك بسرية، ثم اضغط «جاهز»'; side = `<span class="rtag">جاهز ${g.ready.length}/${pv.players.length}</span>`; break;
    case 'night': main = 'حلّ الليل… القاتل يختار أداته ودليله'; break;
    case 'setup': main = myRole() === 'forensic' ? 'دورك: ضع رصاصاتك على بطاقات المشهد' : 'الطبيب الشرعي يفحص مسرح الجريمة'; break;
    case 'talk': {
      const sp = g.talk.order[g.talk.idx];
      const canNext = sp === me || myRole() === 'forensic' || Net.isHost;
      main = `الجولة ${g.round} من ${ROUNDS} · يتكلم: <b>${sp === me ? 'أنت' : nm(sp)}</b>`;
      side = `${g.talk.endsAt ? '<span class="clock" data-timer><b></b></span>' : ''}${canNext ? `<button class="btn sm" data-act="next" data-idx="${g.talk.idx}">${sp === me ? 'انتهيت' : 'التالي'}</button>` : ''}`;
      extra = `<div class="queue wrap" aria-label="ترتيب الكلام">${g.talk.order.map((id, i) => { const p = P(id); return p ? avatar(p, i === g.talk.idx ? 'now' : i < g.talk.idx ? 'done' : '') : ''; }).join('')}</div>`;
      break;
    }
    case 'swap': main = myRole() === 'forensic' ? 'دورك: استبدل بطاقة مشهد بإشارة أوضح' : `انتهت الجولة ${g.round}. الطبيب الشرعي يستبدل بطاقة مشهد`; break;
    case 'hunt': main = 'كُشف القاتل! بقيت له فرصة أخيرة: معرفة الشاهد'; break;
    case 'end': main = g.result.winner === 'good' ? 'انتصرت العدالة' : 'أفلت القاتل'; break;
  }
  return `<div class="phase ph-${ph} ${ph === 'end' ? 'win-' + g.result.winner : ''}"><div class="phase-in wrap"><p>${main}</p><div class="side">${side}</div></div>${extra}</div>`;
}

function phasePanel() {
  const ph = S.pub.phase, r = myRole();
  if (ph === 'roles') return rolesPanel();
  if (ph === 'night') return nightPanel();
  if (ph === 'setup' && r === 'forensic') return editorSetup();
  if (ph === 'swap' && r === 'forensic') return editorSwap();
  if (ph === 'hunt') return huntPanel();
  if (ph === 'end') return endPanel();
  if (r === 'forensic' && ph === 'talk') return `<div class="solbox"><div><p class="eyebrow">أنت الطبيب الشرعي</p><p>ممنوع الكلام والإيماءات. تابع النقاش بصمت، واضغط «التالي» إذا علق الدور.</p></div></div>`;
  if (r === 'spectator') return `<div class="solbox"><div><p class="eyebrow">تشاهد كمتفرج</p><p>انضممت بعد بدء القضية. ستدخل اللعب في القضية القادمة.</p></div></div>`;
  return '';
}

function roleInfoHTML() {
  const pr = S.priv;
  if (!pr || !pr.role) return '<div class="spinner"></div><p class="muted">جارٍ استلام دورك…</p>';
  if (pr.role === 'spectator') return `<h3 class="rn">متفرّج</h3><p>انضممت بعد بدء القضية. شاهد هذه الجولة، وستلعب في القضية القادمة.</p>`;
  const R = ROLES[pr.role];
  const solLine = pr.sol ? `<div class="solline">${cardMini(pr.sol.m, 'm')}${cardMini(pr.sol.c, 'c')}</div>` : '<p class="muted">لم يختر القاتل أداته بعد.</p>';
  let extra = '';
  if (pr.role === 'murderer') extra = (pr.sol ? `<h4>اخترت</h4>${solLine}` : '<p class="muted">ستختار أداتك ودليلك عند حلول الليل.</p>') + (pr.ally ? `<h4>شريكك</h4><p><b>${nm(pr.ally)}</b></p>` : '');
  if (pr.role === 'accomplice') extra = `<h4>القاتل</h4><p><b>${nm(pr.ally)}</b></p><h4>الحل</h4>${solLine}`;
  if (pr.role === 'forensic') extra = pr.sol ? `<h4>القاتل</h4><p><b>${nm(pr.sol.pid)}</b></p><h4>الحل</h4>${solLine}${pr.ally ? `<h4>الشريك</h4><p>${nm(pr.ally)}</p>` : ''}${pr.wit ? `<h4>الشاهد</h4><p>${nm(pr.wit)}</p>` : ''}` : '<p class="muted">ستعرف القاتل والحل بعد أن يختار.</p>';
  if (pr.role === 'witness') extra = `<h4>رأيت هذين يغادران مسرح الجريمة</h4><p><b>${pr.seen.map(nm).join('</b> و <b>')}</b></p><p class="muted">أحدهما القاتل والآخر شريكه، ولا تعرف أيهما القاتل.</p>`;
  return `<p class="team">${R.team === 'good' ? 'فريق العدالة' : 'فريق الجريمة'}</p><h3 class="rn">${R.n}</h3><p>${R.d}</p>${extra}`;
}
const teamCls = () => { const r = myRole(); return r && ROLES[r] ? 't-' + ROLES[r].team : ''; };

function rolesPanel() {
  const ready = S.pub.g.ready.includes(S.me.pid), isP = !!(S.priv && ROLES[S.priv.role]);
  return `<section class="panel">
    <div class="rolecard ${S.g.revealed ? 'open ' + teamCls() : ''}">${S.g.revealed ? roleInfoHTML() : '<div class="back"><span class="seal">سرّي</span><p>تأكد أن لا أحد ينظر إلى شاشتك، ثم اكشف دورك.</p></div>'}</div>
    <div class="row center">
      <button class="btn" data-act="reveal">${S.g.revealed ? 'أخفِ البطاقة' : 'اكشف دوري'}</button>
      ${isP ? `<button class="btn primary" data-act="ready" ${ready || !S.g.seenRole ? 'disabled' : ''}>${ready ? 'بانتظار البقية…' : 'فهمت، جاهز'}</button>` : ''}
    </div>
    ${Net.isHost ? '<div class="row center"><button class="link" data-act="forceNight">ابدأ الليل دون انتظار الجميع</button></div>' : ''}
  </section>`;
}

function pickHand(h, sel, act) {
  return `<div class="pick"><p class="lbl">أداة الجريمة</p><div class="cards">${h.m.map(id => `<button class="card m ${sel.m === id ? 'sel' : ''}" data-act="${act}M" data-id="${id}">${esc(CARD[id].n)}</button>`).join('')}</div>
    <p class="lbl">الدليل الحاسم</p><div class="cards">${h.c.map(id => `<button class="card c ${sel.c === id ? 'sel' : ''}" data-act="${act}C" data-id="${id}">${esc(CARD[id].n)}</button>`).join('')}</div></div>`;
}
function nightPanel() {
  const g = S.pub.g, h = g.hands[S.me.pid], nt = S.g.night, r = myRole();
  if (r === 'murderer' && h) {
    return `<section class="panel night"><div class="moon"></div><h2>أنت القاتل</h2>
      <p>اختر الأداة التي ارتكبت بها الجريمة، والدليل الذي تركته خلفك دون أن تنتبه. سيعرفهما الطبيب الشرعي${g.counts.acc ? ' وشريكك' : ''} فقط.</p>
      ${pickHand(h, nt, 'night')}
      <button class="btn blood big" data-act="nightGo" ${nt.m && nt.c ? '' : 'disabled'}>نفّذ الجريمة</button></section>`;
  }
  if (!h) return `<section class="panel night"><div class="moon"></div><h2>حلّ الليل</h2><p>${r === 'forensic' ? 'انتظر حتى يختار القاتل أداته ودليله، ثم ستظهر لك الحقيقة كاملة.' : 'القاتل يختار الآن…'}</p></section>`;
  return `<section class="panel night"><div class="moon"></div><h2>حلّ الليل</h2>
    <p>${nt.done ? 'تم. بانتظار القاتل… لا تنظر إلى شاشات الآخرين.' : 'حتى لا يُكشف القاتل من حركة يده، اختر أنت أيضاً بطاقتين كما تشاء. اختيارك لا يؤثر على اللعبة.'}</p>
    ${nt.done ? '' : pickHand(h, nt, 'night') + `<button class="btn big" data-act="nightGo" ${nt.m && nt.c ? '' : 'disabled'}>تم</button>`}</section>`;
}

function solBox() {
  const s = S.priv.sol;
  return `<div class="solbox"><div><p class="eyebrow">الحل الذي تعرفه وحدك</p><p>القاتل: <b>${nm(s.pid)}</b></p><div class="solline">${cardMini(s.m, 'm')}${cardMini(s.c, 'c')}</div></div>
    ${S.pub.settings.helper ? `<label class="tog"><input type="checkbox" id="helper-tog" data-set="_helper" ${S.g.helper ? 'checked' : ''}> إظهار المساعد</label>` : ''}
    ${helperOn() ? '<p class="legend"><b class="dm">أ</b> يرتبط بأداة الجريمة &nbsp; <b class="dc">د</b> يرتبط بالدليل الحاسم. الاختيار لك دائماً.</p>' : ''}</div>`;
}
function editorSetup() {
  const pr = S.priv;
  if (!pr || !pr.sol || !pr.offer || !pr.offer.length) return '<section class="panel"><div class="spinner"></div></section>';
  const fx = S.g.fx, hl = helperOn(), nSc = Object.keys(fx.sc).length;
  const done = (fx.cause != null ? 1 : 0) + (fx.loc ? 1 : 0) + nSc;
  return `<section class="panel editor">${solBox()}
    <div class="ed-step"><h3><span>1</span> سبب الوفاة</h3><div class="tiles one">${tileHTML('C', fx.cause, { hl, pick: 'fC' })}</div></div>
    <div class="ed-step"><h3><span>2</span> مكان الجريمة <small>اختر بطاقة واحدة من الأربع وضع فيها رصاصتك.</small></h3>
      <div class="tiles">${LOCS.map(l => tileHTML(l.id, fx.loc && fx.loc.tile === l.id ? fx.loc.opt : null, { hl, pick: 'fL', dim: fx.loc && fx.loc.tile !== l.id })).join('')}</div></div>
    <div class="ed-step"><h3><span>3</span> بطاقات المشهد <small>اختر ٤ من هذه الست وضع رصاصة في كل منها (${nSc}/4). الباقي يُستبعد.</small></h3>
      <div class="tiles">${pr.offer.map(id => tileHTML(id, fx.sc[id] ?? null, { hl, pick: 'fS', dim: nSc >= 4 && fx.sc[id] == null })).join('')}</div></div>
    <div class="ed-go"><span>${done}/6</span><button class="btn primary big" data-act="fGo" ${done === 6 ? '' : 'disabled'}>اعرض الإشارات على المحققين</button></div>
  </section>`;
}
function editorSwap() {
  const g = S.pub.g, pr = S.priv, sw = S.g.sw, hl = helperOn();
  if (!pr || !pr.swapOffer) return '<section class="panel"><div class="spinner"></div></section>';
  return `<section class="panel editor">${solBox()}
    <div class="ed-step"><h3><span>1</span> اختر البطاقة التي ستُزال <small>سبب الوفاة ومكان الجريمة ثابتتان.</small></h3>
      <div class="tiles">${tileHTML('C', g.board.cause.opt, { hl, dim: true })}${tileHTML(g.board.loc.tile, g.board.loc.opt, { hl, dim: true })}
      ${g.board.scenes.map((s, i) => `<div class="swapwrap ${sw.remove === i ? 'rm' : ''}">${tileHTML(s.tile, s.opt, { hl })}<button class="btn sm ${sw.remove === i ? 'blood' : ''}" data-act="swR" data-i="${i}">${sw.remove === i ? 'ستُزال هذه' : 'أزِل هذه'}</button></div>`).join('')}</div></div>
    <div class="ed-step"><h3><span>2</span> اختر بطاقة جديدة وضع رصاصتك <small>اختر واحدة فقط من الثلاث.</small></h3>
      <div class="tiles">${pr.swapOffer.map(id => tileHTML(id, sw.tile === id ? sw.opt : null, { hl, pick: 'swP', dim: sw.tile && sw.tile !== id })).join('')}</div></div>
    <div class="ed-go"><button class="btn primary big" data-act="swGo" ${sw.remove != null && sw.tile ? '' : 'disabled'}>ابدأ الجولة ${g.round + 1}</button></div>
  </section>`;
}

function huntPanel() {
  const g = S.pub.g, pr = S.priv, r = myRole();
  const cands = S.pub.players.filter(p => g.hands[p.id] && p.id !== g.evil.m && p.id !== g.evil.a);
  const head = `<h2>كُشف القاتل</h2><p><b>${nm(g.hero)}</b> حلّ القضية: القاتل هو <b>${nm(g.evil.m)}</b>${g.evil.a ? ` وشريكه <b>${nm(g.evil.a)}</b>` : ''}. لكن إن عرف القاتل من هو الشاهد فسيُسكته ويفلت بجريمته.</p>`;
  if (r === 'murderer' || r === 'accomplice') {
    const sel = S.g.hunt, sug = pr && pr.suggest;
    return `<section class="panel">${head}
      <p class="lbl">${r === 'murderer' ? 'من هو الشاهد برأيك؟ القرار لك وحدك' : 'اقترح على القاتل من تظنه الشاهد'}</p>
      <div class="who-list">${cands.map(p => `<button class="who ${(r === 'murderer' ? sel : sug) === p.id ? 'sel' : ''}" data-act="${r === 'murderer' ? 'huntPick' : 'suggest'}" data-pid="${p.id}">${avatar(p)}<span>${esc(p.name)}</span>${sug === p.id ? '<em>اقتراح الشريك</em>' : ''}</button>`).join('')}</div>
      ${r === 'murderer' ? `<button class="btn blood big" data-act="huntGo" ${sel ? '' : 'disabled'}>هذا هو الشاهد</button>` : ''}</section>`;
  }
  return `<section class="panel">${head}<p>${r === 'witness' ? 'تماسك، ولا تكشف نفسك بنظرة أو كلمة.' : 'القاتل يتشاور مع شريكه الآن… حاولوا تضليله!'}</p></section>`;
}

function linksHTML() {
  const g = S.pub.g, s = g.sol;
  if (!g.board || !s) return '';
  const mT = CARD[s.m].tags, cT = CARD[s.c].tags;
  const all = [{ tile: 'C', opt: g.board.cause.opt }, g.board.loc, ...g.board.scenes];
  return `<ul class="links">${all.map(x => {
    const o = TILE[x.tile].o[x.opt];
    const hm = o.tags.filter(t => mT.includes(t)), hc = o.tags.filter(t => cT.includes(t));
    return `<li><span class="lt">${esc(TILE[x.tile].title)}</span><span class="lo">${esc(o.n)}</span><span class="lk">${hm.length ? `<em class="km">الأداة: ${hm.map(t => TAG_AR[t]).join('، ')}</em>` : ''}${hc.length ? `<em class="kc">الدليل: ${hc.map(t => TAG_AR[t]).join('، ')}</em>` : ''}${!hm.length && !hc.length ? '<em class="kn">إشارة عامة</em>' : ''}</span></li>`;
  }).join('')}</ul>`;
}
function endPanel() {
  const pv = S.pub, g = pv.g, res = g.result, s = g.sol;
  const reasons = {
    solved: `<b>${nm(g.hero)}</b> كشف الأداة والدليل بدقة.`,
    missed: `القاتل اتهم <b>${nm(res.huntTarget)}</b> بأنه الشاهد، وأخطأ. الشاهد نجا.`,
    witness: `كُشف القاتل، لكنه عرف أن <b>${nm(res.huntTarget)}</b> هو الشاهد فأسكته.`,
    time: 'انتهت الجولات الثلاث دون أن يحل أحد القضية.',
    nobadges: 'استُنفدت كل شارات المحققين دون اتهام صحيح.'
  };
  const order = { forensic: 0, murderer: 1, accomplice: 2, witness: 3, investigator: 4 };
  const rl = pv.players.filter(p => g.roles[p.id]).sort((a, b) => order[g.roles[a.id]] - order[g.roles[b.id]]);
  const sc = [...pv.players].sort((a, b) => (pv.scores[b.id] || 0) - (pv.scores[a.id] || 0));
  return `<section class="panel">
    <div class="verdict-banner ${res.winner}"><p class="eyebrow">${res.winner === 'good' ? 'فاز فريق العدالة' : 'فاز فريق الجريمة'}</p><h2>${res.winner === 'good' ? 'انتصرت العدالة' : 'أفلت القاتل'}</h2><p>${reasons[res.reason] || ''}</p></div>
    <div class="end-grid">
      <div class="end-box"><h3>الحقيقة</h3><p>القاتل: <b>${nm(s.pid)}</b></p><div class="solline" style="justify-content:flex-start">${cardMini(s.m, 'm')}${cardMini(s.c, 'c')}</div>
        <h3>الأدوار</h3><ul class="roles-list">${rl.map(p => `<li>${avatar(p)}<span>${esc(p.name)}</span><span class="rtag ${ROLES[g.roles[p.id]].team}">${ROLES[g.roles[p.id]].n}</span></li>`).join('')}</ul></div>
      <div class="end-box"><h3>كيف ربط الطبيب الشرعي الإشارات</h3><p class="muted">الصفات المشتركة بين كل رصاصة والحل.</p>${linksHTML()}</div>
      <div class="end-box"><h3>النقاط</h3><p class="muted">نقطة لكل فائز، ونقطة إضافية لمن كشف الحل.</p><ul class="scores">${sc.map(p => `<li>${avatar(p)}<span>${esc(p.name)}</span><b>${pv.scores[p.id] || 0}</b></li>`).join('')}</ul>
        ${Net.isHost ? '<button class="btn primary big" data-act="newgame">قضية جديدة</button>' : '<p class="wait">بانتظار المضيف لبدء قضية جديدة…</p>'}</div>
    </div></section>`;
}

function boardSection() {
  const pv = S.pub, g = pv.g, ph = pv.phase, r = myRole();
  if (ph === 'roles' || ph === 'night') return '';
  if (!g.board) {
    if (r === 'forensic') return '';
    return `<section class="board empty"><div class="lens"></div><h2>مسرح الجريمة مغلق</h2><p>الطبيب الشرعي يضع إشاراته الآن. ادرسوا بطاقات المشتبه بهم في الأثناء.</p></section>`;
  }
  if (r === 'forensic' && ph === 'swap') return '';
  const b = g.board, hl = helperOn();
  return `<section class="board"><div class="sec-h"><h2>مسرح الجريمة</h2><p>الرصاصة تحدد اختيار الطبيب الشرعي في كل بطاقة</p></div><div class="tiles">
    ${tileHTML('C', b.cause.opt, { hl })}${tileHTML(b.loc.tile, b.loc.opt, { hl })}${b.scenes.map(s => tileHTML(s.tile, s.opt, { hl, fresh: ph !== 'end' && s.r > 1 && s.r === g.round })).join('')}
  </div></section>`;
}

function knownTag(pid) {
  const pv = S.pub, g = pv.g, pr = S.priv, me = S.me.pid;
  if (pv.phase === 'end' && g.roles) { const R = ROLES[g.roles[pid]]; return `<span class="rtag ${R.team}">${R.n}</span>`; }
  if (g.evil) { if (pid === g.evil.m) return '<span class="rtag evil">القاتل</span>'; if (pid === g.evil.a) return '<span class="rtag evil">الشريك</span>'; }
  if (!pr) return '';
  if ((pr.role === 'murderer' || pr.role === 'accomplice') && pid === pr.ally) return `<span class="rtag evil">${pr.role === 'murderer' ? 'شريكك' : 'القاتل'}</span>`;
  if (pr.role === 'forensic' && pr.sol && pid === pr.sol.pid) return '<span class="rtag evil">القاتل</span>';
  if (pr.role === 'forensic' && pid === pr.ally) return '<span class="rtag evil">الشريك</span>';
  if (pr.role === 'witness' && pr.seen && pr.seen.includes(pid)) return '<span class="rtag sus">رأيته</span>';
  if (pid === me && pr.role === 'murderer') return '';
  return '';
}
function suspectsSection() {
  const pv = S.pub, g = pv.g, ph = pv.phase, me = S.me.pid, pr = S.priv;
  if (ph === 'roles') return '';
  const sp = ph === 'talk' && g.talk ? g.talk.order[g.talk.idx] : null;
  const solFor = ph === 'end' ? g.sol : (pr && pr.sol && ['murderer', 'accomplice', 'forensic'].includes(pr.role) ? pr.sol : null);
  const list = pv.players.filter(p => g.hands[p.id]);
  const f = P(g.forensic);
  return `<section class="suspects"><div class="sec-h"><h2>المشتبه بهم</h2><div class="legend-row"><span><i class="m"></i>أدوات الجريمة</span><span><i class="c"></i>الأدلة</span>${f ? `<span>الطبيب الشرعي: ${esc(f.name)}</span>` : ''}</div></div>
    <p class="fz" style="margin:-4px 0 12px">اضغط على أي بطاقة لتدوين ملاحظتك الخاصة: مرة للاستبعاد، ومرتين للاشتباه. لا يراها غيرك.</p>
    <div class="dossiers">${list.map(p => {
      const h = g.hands[p.id], badge = g.badges[p.id];
      const chip = (id, k) => { const n = S.notes[p.id + ':' + id] || 0; const sol = solFor && solFor.pid === p.id && (solFor.m === id || solFor.c === id); return `<button class="card ${k} n${n} ${sol ? 'sol' : ''}" data-act="note" data-k="${p.id}:${id}">${esc(CARD[id].n)}</button>`; };
      return `<article class="dossier ${sp === p.id ? 'speaking' : ''} ${p.on ? '' : 'off'} ${ph === 'end' && g.sol && g.sol.pid === p.id ? 'culprit' : ''}">
        <header>${avatar(p)}<h4>${esc(p.name)}${p.id === me ? ' <small>(أنت)</small>' : ''}${p.on ? '' : ' <small>غير متصل</small>'}</h4>${knownTag(p.id)}
          <span class="badge ${badge ? '' : 'used'}" title="${badge ? 'لديه شارة اتهام' : 'استخدم شارته'}" aria-label="${badge ? 'لديه شارة اتهام' : 'استخدم شارته'}">${ICON.badge}</span>
          ${sp === p.id && g.talk.endsAt ? '<span class="clock" data-timer><b></b></span>' : ''}</header>
        <div class="hand"><div class="cards">${h.m.map(id => chip(id, 'm')).join('')}</div><div class="cards">${h.c.map(id => chip(id, 'c')).join('')}</div></div>
      </article>`;
    }).join('')}</div></section>`;
}

function logSection() {
  const g = S.pub.g;
  const items = (g.log || []).filter(l => l.t === 'accuse' || l.t === 'swap');
  if (!items.length) return '';
  return `<section class="log"><h2>سجل التحقيق</h2><ol>${items.map(l => l.t === 'accuse'
    ? `<li class="${l.ok ? 'ok' : 'bad'}"><b>${nm(l.by)}</b> اتهم <b>${nm(l.target)}</b> بـ«${esc(CARD[l.m].n)}» و«${esc(CARD[l.c].n)}»: ${l.ok ? 'اتهام صحيح' : 'اتهام خاطئ'}</li>`
    : `<li>الجولة ${l.r}: بطاقة مشهد جديدة «${esc(TILE[l.tile].title)}»</li>`).join('')}</ol></section>`;
}

function actionBar() {
  const pv = S.pub, g = pv.g, me = S.me.pid, ph = pv.phase;
  const hasHand = !!g.hands[me];
  const canAcc = hasHand && ['talk', 'swap'].includes(ph) && g.badges[me];
  return `<nav class="bar"><div class="bar-in wrap">
    ${S.priv && S.priv.role && S.priv.role !== 'spectator' ? `<button class="btn" data-act="role">${ICON.eye}<span>بطاقتي السرية</span></button>` : ''}
    <div class="reacts">${REACTS.map(r => `<button class="re" data-act="react" data-e="${r}" aria-label="تفاعل ${r}">${r}</button>`).join('')}</div>
    ${hasHand ? `<button class="btn accuse" data-act="accOpen" ${canAcc ? '' : 'disabled'}>${ICON.badge}<span>${g.badges[me] ? 'اتهام' : 'استُخدمت شارتك'}</span></button>` : ''}
  </div></nav>`;
}

/* ---------- النوافذ ---------- */
let lastModal = null;
function modalWrap(title, body) {
  const enter = lastModal !== S.ui.modal;
  lastModal = S.ui.modal;
  return `<div class="modal" data-act="closeBg" role="dialog" aria-modal="true" aria-label="${esc(title)}"><div class="sheet ${enter ? 'enter' : ''}"><header><h2>${title}</h2><button class="x" data-act="close" aria-label="إغلاق">×</button></header><div class="sheet-b">${body}</div></div></div>`;
}
function modalHTML() {
  if (!S.ui.modal) lastModal = null;
  switch (S.ui.modal) {
    case 'rules': return modalWrap('كيف نلعب؟', RULES_HTML);
    case 'qr': {
      const qr = qrSVG(inviteLink());
      return modalWrap('ادخل الغرفة', `<div class="qr-big">${qr || ''}<div class="bigcode" dir="ltr">${esc(Net.code)}</div><p>وجّه كاميرا الجوال نحو الباركود، ثم اضغط الرابط الذي يظهر.</p>${S.pub && S.pub.phase !== 'lobby' ? '<p class="muted">القضية بدأت: من يدخل الآن يشاهد كمتفرج، ويلعب في القضية القادمة.</p>' : ''}</div>`);
    }
    case 'role': return modalWrap('بطاقتي السرية', `<div class="rolecard ${teamCls()}">${roleInfoHTML()}</div>`);
    case 'accuse': return accuseModal();
    case 'menu': return modalWrap('القائمة', `
      <button class="btn" data-act="rules">كيف نلعب؟</button>
      ${S.pub && window.qrcode ? '<button class="btn" data-act="qrBig">اعرض باركود الدعوة</button>' : ''}
      ${S.pub ? '<button class="btn" data-act="copy">انسخ رابط الدعوة</button>' : ''}
      ${Net.isHost && S.pub && S.pub.g && S.pub.phase !== 'end' ? '<button class="btn" data-act="abort">أنهِ القضية وعُد لغرفة الانتظار</button>' : ''}
      ${S.room ? '<button class="btn blood" data-act="leave">غادر الغرفة</button>' : ''}
      ${Net.isHost ? '<p class="muted">أنت المضيف: جهازك يدير اللعبة. إن أغلقت الصفحة تتوقف اللعبة حتى تفتح الرابط من جديد، وتعود من حيث توقفتم.</p>' : ''}`);
  }
  return '';
}
function accuseModal() {
  const g = S.pub.g, me = S.me.pid, a = S.g.acc || {};
  const sus = S.pub.players.filter(p => g.hands[p.id] && p.id !== me);
  let body = `<p class="muted">لديك شارة واحدة فقط. إن أخطأت تفقد حقك في الاتهام حتى نهاية القضية، لكن يمكنك متابعة النقاش.</p>
    <p class="lbl">١. المتهم</p><div class="who-list">${sus.map(p => `<button class="who ${a.t === p.id ? 'sel' : ''}" data-act="accT" data-pid="${p.id}">${avatar(p)}<span>${esc(p.name)}</span></button>`).join('')}</div>`;
  if (a.t && g.hands[a.t]) {
    const h = g.hands[a.t];
    body += `<p class="lbl">٢. أداة الجريمة</p><div class="cards">${h.m.map(id => `<button class="card m ${a.m === id ? 'sel' : ''}" data-act="accM" data-id="${id}">${esc(CARD[id].n)}</button>`).join('')}</div>
      <p class="lbl">٣. الدليل الحاسم</p><div class="cards">${h.c.map(id => `<button class="card c ${a.c === id ? 'sel' : ''}" data-act="accC" data-id="${id}">${esc(CARD[id].n)}</button>`).join('')}</div>`;
  }
  body += `<button class="btn blood big" data-act="accGo" ${a.t && a.m && a.c ? '' : 'disabled'}>أؤكد الاتهام</button>`;
  return modalWrap('اتهام رسمي', body);
}

const RULES_HTML = `
<p>وقعت جريمة قتل، والقاتل يجلس بينكم. أمام كل لاعب ٤ بطاقات <b>أدوات جريمة</b> (حمراء) و٤ بطاقات <b>أدلة</b> (زرقاء)، وكلها ظاهرة للجميع.</p>
<h3>الأدوار</h3>
<ul>
<li><b>الطبيب الشرعي:</b> يعرف الحل كاملاً، ولا يحق له الكلام أبداً. يتواصل فقط بوضع رصاصات على بطاقات المشهد.</li>
<li><b>القاتل:</b> يختار سراً أداة واحدة ودليلاً واحداً من بطاقاته، ثم يضلّل الجميع.</li>
<li><b>الشريك</b> (من ٦ لاعبين): يعرف القاتل والحل ويساعده.</li>
<li><b>الشاهد</b> (من ٦ لاعبين): رأى القاتل وشريكه دون أن يعرف أيهما القاتل.</li>
<li><b>المحققون:</b> البقية. هدفهم كشف الحل.</li>
</ul>
<h3>سير القضية</h3>
<ol>
<li>كل لاعب يكشف دوره بسرية.</li>
<li><b>الليل:</b> القاتل يختار أداته ودليله، والبقية يتظاهرون بالاختيار للتمويه.</li>
<li><b>الطبيب الشرعي</b> يضع رصاصة في بطاقة سبب الوفاة، وفي بطاقة مكان يختارها من أربع، وفي ٤ بطاقات مشهد يختارها من ست.</li>
<li><b>ثلاث جولات نقاش:</b> يتكلم كل لاعب بدوره، يحلل الإشارات ويدافع ويتهم. بعد الجولتين الأولى والثانية يستبدل الطبيب الشرعي بطاقة مشهد بأخرى أوضح.</li>
<li><b>الاتهام:</b> في أي وقت، تختار لاعباً وأداة ودليلاً من بطاقاته. لكل لاعب شارة واحدة فقط، والقاتل يملك شارة أيضاً ويمكنه الاتهام للتمويه.</li>
</ol>
<h3>الفوز</h3>
<ul>
<li>يفوز <b>فريق العدالة</b> إذا حدد أحد المحققين الأداة والدليل الصحيحين معاً.</li>
<li>لكن إن كان الشاهد في اللعبة، يحصل القاتل على فرصة أخيرة: إن عرف من هو الشاهد يفوز فريق الجريمة.</li>
<li>يفوز <b>فريق الجريمة</b> إذا انتهت الجولات الثلاث أو نفدت شارات المحققين دون حل.</li>
</ul>
<h3>نصائح</h3>
<ul>
<li>العبوا في نفس المكان أو في مكالمة صوتية؛ النقاش هو قلب اللعبة.</li>
<li>الطبيب الشرعي ممنوع من الكلام والإيماءات وتعابير الوجه تماماً.</li>
<li>اضغط على بطاقات المشتبه بهم لتدوين ملاحظاتك: مرة للاستبعاد، ومرتين للاشتباه.</li>
</ul>`;

/* ================= الرسم ================= */
function render() {
  let html;
  if (S.err === 'net') html = viewCenter('تعذّر الاتصال', 'لم نستطع الوصول إلى خادم الغرف. تأكد من اتصالك بالإنترنت ثم أعد المحاولة.', false, '<button class="btn primary" data-act="retry">أعد المحاولة</button>');
  else if (S.err === 'notfound') html = viewCenter('الغرفة غير موجودة', 'لم نجد غرفة بهذا الرمز، أو أن المضيف أغلقها. تأكد من الرابط أو اطلب رابطاً جديداً.', false, '<div class="row center"><button class="btn primary" data-act="retry">أعد المحاولة</button><button class="btn" data-act="leave">الصفحة الرئيسية</button></div>');
  else if (!S.room) html = viewHome() + modalHTML();
  else if (!S.pub) html = viewCenter(S.status === 'creating' ? 'نفتح ملف القضية…' : 'ندخل الغرفة…', 'لحظات قليلة', true);
  else if (S.pub.phase === 'lobby') html = viewLobby();
  else html = viewGame();
  const sy = window.scrollY;
  $('#app').innerHTML = html;
  window.scrollTo(0, sy);
  tickTimers();
}

let lastTickSec = null;
function tickTimers() {
  const pv = S.pub;
  if (!pv || pv.phase !== 'talk' || !pv.g.talk || !pv.g.talk.endsAt) return;
  const left = Math.max(0, pv.g.talk.endsAt - (Date.now() + S.offset));
  const sec = Math.ceil(left / 1000), total = pv.settings.timer * 1000 || 1;
  document.querySelectorAll('[data-timer]').forEach(el => {
    el.style.setProperty('--p', Math.min(1, left / total).toFixed(3));
    el.classList.toggle('low', sec <= 10);
    el.firstElementChild.textContent = sec;
  });
  if (sec !== lastTickSec) {
    lastTickSec = sec;
    if (sec <= 5 && sec > 0 && pv.g.talk.order[pv.g.talk.idx] === S.me.pid) Snd.play('tick');
  }
}
setInterval(() => {
  tickTimers();
  if (Net.isHost && H && H.phase === 'talk' && H.game.talk && H.game.talk.endsAt && Date.now() > H.game.talk.endsAt) { advanceTalk(); hostCommit(); }
}, 250);

/* ================= معالجات الأزرار ================= */
const ACT = {
  color: d => { S.form.color = d.c; render(); },
  create: () => createRoom(),
  join: () => {
    const code = (S.form.code || '').trim().toUpperCase();
    if (!S.form.name.trim()) { toast('اكتب اسمك أولاً'); return; }
    if (!/^[A-Z0-9]{5}$/.test(code)) { toast('رمز الغرفة من ٥ أحرف'); return; }
    enterRoom(code, 0);
  },
  joinHash: () => { if (!S.form.name.trim()) { toast('اكتب اسمك أولاً'); return; } enterRoom(S.pendingJoin.code, S.pendingJoin.b); },
  clearHash: () => { S.pendingJoin = null; history.replaceState(null, '', location.pathname + (SLOT ? '#~' + SLOT : '')); render(); },
  rules: () => { S.ui.modal = 'rules'; render(); },
  menu: () => { S.ui.modal = 'menu'; render(); },
  qrBig: () => { S.ui.modal = 'qr'; render(); },
  close: () => { S.ui.modal = null; render(); },
  closeBg: (d, el, e) => { if (e.target === el) { S.ui.modal = null; render(); } },
  snd: () => { Snd.on = !Snd.on; store.set('_snd', Snd.on); Snd.init(); Snd.play('pop'); render(); },
  copy: () => {
    const link = inviteLink();
    const ok = () => toast('نُسخ رابط الدعوة');
    try { navigator.clipboard.writeText(link).then(ok, () => window.prompt('انسخ الرابط:', link)); } catch (e) { window.prompt('انسخ الرابط:', link); }
  },
  share: () => { navigator.share({ title: 'الدليل الحاسم', text: 'تعال العب معنا «الدليل الحاسم»! رمز الغرفة: ' + Net.code, url: inviteLink() }).catch(() => { }); },
  kick: d => send({ type: 'kick', pid: d.pid }),
  start: () => send({ type: 'start' }),
  reveal: () => { S.g.revealed = !S.g.revealed; if (S.g.revealed) S.g.seenRole = true; render(); },
  ready: () => send({ type: 'ready' }),
  forceNight: () => send({ type: 'forceNight' }),
  nightM: d => { S.g.night.m = d.id; render(); },
  nightC: d => { S.g.night.c = d.id; render(); },
  nightGo: () => {
    const nt = S.g.night; if (!nt.m || !nt.c) return;
    if (myRole() === 'murderer') send({ type: 'pick', m: nt.m, c: nt.c });
    else { nt.done = true; render(); }
  },
  fC: d => { const o = +d.opt, fx = S.g.fx; fx.cause = fx.cause === o ? null : o; render(); },
  fL: d => { const o = +d.opt, fx = S.g.fx; fx.loc = fx.loc && fx.loc.tile === d.tile && fx.loc.opt === o ? null : { tile: d.tile, opt: o }; render(); },
  fS: d => {
    const o = +d.opt, sc = S.g.fx.sc;
    if (sc[d.tile] === o) delete sc[d.tile];
    else if (sc[d.tile] == null && Object.keys(sc).length >= 4) { toast('اخترت ٤ بطاقات. ألغِ رصاصة من إحداها أولاً'); return; }
    else sc[d.tile] = o;
    render();
  },
  fGo: () => {
    const fx = S.g.fx, ids = Object.keys(fx.sc);
    if (fx.cause == null || !fx.loc || ids.length !== 4) return;
    send({ type: 'setup', b: { cause: fx.cause, loc: fx.loc, scenes: ids.map(t => ({ tile: t, opt: fx.sc[t] })) } });
  },
  swR: d => { const i = +d.i; S.g.sw.remove = S.g.sw.remove === i ? null : i; render(); },
  swP: d => { const sw = S.g.sw, o = +d.opt; if (sw.tile === d.tile && sw.opt === o) { sw.tile = null; sw.opt = null; } else { sw.tile = d.tile; sw.opt = o; } render(); },
  swGo: () => { const sw = S.g.sw; if (sw.remove == null || !sw.tile) return; send({ type: 'swap', remove: sw.remove, tile: sw.tile, opt: sw.opt }); },
  next: d => send({ type: 'next', idx: +d.idx }),
  accOpen: () => { S.g.acc = {}; S.ui.modal = 'accuse'; render(); },
  accT: d => { S.g.acc = { t: d.pid }; render(); },
  accM: d => { S.g.acc.m = d.id; render(); },
  accC: d => { S.g.acc.c = d.id; render(); },
  accGo: () => { const a = S.g.acc; if (!a || !a.t || !a.m || !a.c) return; send({ type: 'accuse', target: a.t, m: a.m, c: a.c }); S.ui.modal = null; render(); },
  note: d => {
    const k = d.k; S.notes[k] = ((S.notes[k] || 0) + 1) % 3;
    if (!S.notes[k]) delete S.notes[k];
    store.set('_notes_' + S.pub.code + '_' + S.gid, S.notes);
    render();
  },
  react: d => react(d.e),
  role: () => { S.ui.modal = 'role'; render(); },
  huntPick: d => { S.g.hunt = d.pid; render(); },
  huntGo: () => { if (S.g.hunt) send({ type: 'hunt', target: S.g.hunt }); },
  suggest: d => send({ type: 'suggest', target: d.pid }),
  newgame: () => send({ type: 'newgame' }),
  abort: () => { if (window.confirm('إنهاء القضية الحالية والعودة لغرفة الانتظار؟')) { S.ui.modal = null; send({ type: 'abort' }); } },
  leave: () => {
    if (Net.isHost && !window.confirm('أنت المضيف. إن غادرت تتوقف اللعبة عند الجميع حتى تعود بفتح الرابط. هل تريد المغادرة؟')) return;
    try { Net.c && Net.c.end(true); } catch (e) { }
    Object.assign(Net, { c: null, code: null, isHost: false, hostPub: null, key: null, hostOn: false, pendingPriv: null, seenHost: false });
    H = null; S.room = null; S.pub = null; S.priv = null; S.err = null; S.pendingJoin = null; S.ui.modal = null; S.evLast = null; S.gid = null;
    history.replaceState(null, '', location.pathname + (SLOT ? '#~' + SLOT : ''));
    render();
  },
  retry: () => location.reload()
};

document.addEventListener('click', e => {
  Snd.init();
  const el = e.target.closest('[data-act]');
  if (!el || el.disabled) return;
  const fn = ACT[el.dataset.act];
  if (fn) fn(el.dataset, el, e);
});
document.addEventListener('input', e => {
  if (e.target.id === 'nm') S.form.name = e.target.value;
  if (e.target.id === 'code') { S.form.code = e.target.value.toUpperCase(); }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && S.ui.modal) { S.ui.modal = null; render(); }
  if (e.key === 'Enter' && e.target.id === 'code') ACT.join();
  if (e.key === 'Enter' && e.target.id === 'nm') { if (S.pendingJoin) ACT.joinHash(); }
});
document.addEventListener('change', e => {
  const el = e.target, k = el.dataset.set;
  if (!k) return;
  if (k === '_helper') { S.g.helper = el.checked; render(); return; }
  const v = el.type === 'checkbox' ? el.checked : (k === 'timer' ? +el.value : el.value);
  send({ type: 'settings', s: { [k]: v } });
});
$('#stage').addEventListener('click', () => { stageDone && stageDone(); });

/* إبقاء الشاشة مضاءة أثناء اللعب */
let wakeLock = null;
async function keepAwake() {
  try { if ('wakeLock' in navigator && !wakeLock && S.pub && S.pub.phase !== 'lobby') { wakeLock = await navigator.wakeLock.request('screen'); wakeLock.addEventListener('release', () => { wakeLock = null; }); } } catch (e) { }
}
document.addEventListener('pointerdown', keepAwake);
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') keepAwake(); });

/* ================= الإقلاع ================= */
(function boot() {
  const prof = store.get('_profile');
  if (prof) { S.form.name = prof.name || ''; if (COLORS.includes(prof.color)) S.form.color = prof.color; }
  if (!window.mqtt) { S.err = 'net'; render(); return; }
  const h = BOOT_HASH;
  if (h) {
    const hs = store.get('_host_' + h.code), id = store.get('_id_' + h.code);
    if (hs && id && hs.hostId === id.pid) { resumeHost(hs, id); return; }
    if (id && prof && prof.name) { enterRoom(h.code, h.b); return; }
    S.pendingJoin = h;
  }
  render();
})();
