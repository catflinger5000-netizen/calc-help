(() => {
  'use strict';

  const FIREBASE_CONFIG = {
    apiKey: 'AIzaSyDfIuq7GB53dIyFbE2sp7uDtYnJF3IlwkQ',
    authDomain: 'calc-help.firebaseapp.com',
    projectId: 'calc-help',
    storageBucket: 'calc-help.firebasestorage.app',
    messagingSenderId: '748499599156',
    appId: '1:748499599156:web:bd2607535dd24431baaf61',
  };

  const SALT = 'calc-help-room-v1-5e1c07b2a94f3d68';
  const ITERATIONS = 600000;
  const CHECK = 'f886f34f6d3309128beaea32de3774394c591011815289b6c7d63afa98f936df';
  const WINDOW = 200;
  const MAX_SEALED = 7900;
  const NAME_KEY = 'calc-name';

  const $ = (id) => document.getElementById(id);
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const toBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const fromBase64 = (text) => Uint8Array.from(atob(text), (char) => char.charCodeAt(0));

  let room = null;
  let stopListening = null;
  let loadTimer = null;
  let oldestAt = null;
  let queue = Promise.resolve();
  let busy = false;
  const rows = new Map();

  // The password gives the encryption key, the database room and a check
  // value. Only the check value is in this file, so the password is not.
  async function deriveRoom(password) {
    const base = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: encoder.encode(SALT), iterations: ITERATIONS },
      base,
      768,
    ));
    const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    const hex = [...bits.slice(32)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
    return { key, id: `r${hex.slice(0, 40)}`, check: hex.slice(64, 128) };
  }

  async function seal(value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = encoder.encode(JSON.stringify(value));
    const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, room.key, data);
    return { iv: toBase64(iv), ct: toBase64(new Uint8Array(sealed)) };
  }

  async function unseal(box) {
    const opened = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(box.iv) },
      room.key,
      fromBase64(box.ct),
    );
    return JSON.parse(decoder.decode(opened));
  }

  function messages() {
    if (!window.firebase) throw new Error('unavailable');
    if (!firebase.apps.length) firebase.initializeApp(FIREBASE_CONFIG);
    return firebase.firestore().collection('rooms').doc(room.id).collection('msgs');
  }

  function readName() {
    try {
      return localStorage.getItem(NAME_KEY) || '';
    } catch {
      return '';
    }
  }

  function writeName(value) {
    try {
      localStorage.setItem(NAME_KEY, value);
    } catch {
      // The name just isn't remembered on this device.
    }
  }

  function closeGate() {
    $('gate').hidden = true;
    $('gate-input').value = '';
    $('gate-error').textContent = '';
  }

  function clearLog() {
    rows.clear();
    oldestAt = null;
    $('dm-log').querySelectorAll('.msg').forEach((row) => row.remove());
    $('dm-empty').hidden = false;
    $('dm-older').hidden = true;
  }

  function addRow(id, at, message) {
    const row = document.createElement('article');
    row.className = 'msg';
    row.dataset.at = String(at);
    if (message.name === $('dm-name').value.trim()) row.classList.add('mine');

    const meta = document.createElement('p');
    meta.className = 'msg-meta';
    const time = new Date(at).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    meta.textContent = `${message.name} · ${time}`;

    const text = document.createElement('p');
    text.className = 'msg-text';
    text.textContent = message.text;
    row.append(meta, text);

    const log = $('dm-log');
    const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
    const later = [...log.querySelectorAll('.msg')].find((other) => Number(other.dataset.at) > at);
    log.insertBefore(row, later || null);
    rows.set(id, row);
    $('dm-empty').hidden = true;
    if (atBottom) log.scrollTop = log.scrollHeight;
  }

  async function receive(doc) {
    if (rows.has(doc.id)) return;
    const body = doc.data();
    if (typeof body.at !== 'number') return;
    if (oldestAt === null || body.at < oldestAt) oldestAt = body.at;
    try {
      const message = await unseal(body);
      if (typeof message.name === 'string' && typeof message.text === 'string') addRow(doc.id, body.at, message);
    } catch {
      // Anything not encrypted with this password is ignored.
    }
  }

  function startListening() {
    const status = $('dm-status');
    const stalled = "Can't reach messages yet.";
    loadTimer = setTimeout(() => { status.textContent = stalled; }, 10000);

    stopListening = messages().orderBy('at').limitToLast(WINDOW).onSnapshot(
      (snap) => {
        if (!snap.metadata.fromCache) {
          clearTimeout(loadTimer);
          if (status.textContent === stalled) status.textContent = '';
        }
        const added = snap.docChanges().filter((change) => change.type === 'added').map((change) => change.doc);
        if (snap.size >= WINDOW && rows.size === 0) $('dm-older').hidden = false;
        queue = queue.then(async () => {
          for (const doc of added) await receive(doc);
        });
      },
      () => {
        clearTimeout(loadTimer);
        status.textContent = 'Messages stopped updating. Reload the page.';
      },
    );
  }

  async function loadOlder() {
    const older = await messages().orderBy('at').endBefore(oldestAt).limitToLast(WINDOW).get();
    for (const doc of older.docs) await receive(doc);
    $('dm-older').hidden = older.size < WINDOW;
  }

  function openDm() {
    closeGate();
    $('dm').hidden = false;
    startListening();
    $('dm-text').focus();
  }

  function closeDm() {
    $('dm').hidden = true;
    clearTimeout(loadTimer);
    if (stopListening) stopListening();
    stopListening = null;
    clearLog();
    $('dm-status').textContent = '';
  }

  async function send() {
    const input = $('dm-text');
    const text = input.value.trim();
    if (!text || busy) return;

    busy = true;
    const status = $('dm-status');
    try {
      const name = $('dm-name').value.trim() || 'anon';
      const box = await seal({ name, text });
      if (box.ct.length > MAX_SEALED) {
        status.textContent = 'Message is too long. Split it in two.';
        return;
      }
      await messages().doc().set({ at: Date.now(), ...box });
      input.value = '';
      status.textContent = '';
    } catch {
      status.textContent = 'Message not sent. Try again.';
    } finally {
      busy = false;
    }
  }

  $('spot').addEventListener('click', () => {
    if (room) {
      openDm();
      return;
    }
    $('gate').hidden = false;
    $('gate-input').focus();
  });

  $('gate-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;

    busy = true;
    try {
      const candidate = await deriveRoom($('gate-input').value);
      if (candidate.check !== CHECK) {
        $('gate-error').textContent = 'Wrong password.';
        $('gate-input').select();
        return;
      }
      room = candidate;
      openDm();
    } catch {
      $('gate-error').textContent = 'Could not open this. Try again.';
    } finally {
      busy = false;
    }
  });

  $('dm-name').value = readName();
  $('dm-name').addEventListener('change', () => writeName($('dm-name').value.trim()));

  $('dm-form').addEventListener('submit', (event) => {
    event.preventDefault();
    send();
  });
  $('dm-text').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      send();
    }
  });

  $('dm-older').addEventListener('click', () => {
    loadOlder().catch(() => { $('dm-status').textContent = "Couldn't load older messages."; });
  });
  $('dm-close').addEventListener('click', closeDm);
  $('dm-lock').addEventListener('click', () => {
    closeDm();
    room = null;
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    if (!$('dm').hidden) closeDm();
    else if (!$('gate').hidden) closeGate();
  });
})();
