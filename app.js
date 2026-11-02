(() => {
  'use strict';

  const RELAY = 'https://ntfy.sh';
  const SALT = 'calc-help-room-v1-5e1c07b2a94f3d68';
  const ITERATIONS = 600000;
  const MIN_PASSWORD = 16;
  const MAX_BODY = 3900;
  const MAX_SAVED = 5000;
  const NAME_KEY = 'calc-name';

  const $ = (id) => document.getElementById(id);
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const toBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const fromBase64 = (text) => Uint8Array.from(atob(text), (char) => char.charCodeAt(0));

  let room = null;
  let stream = null;
  let queue = Promise.resolve();
  let busy = false;
  const rows = new Map();

  // The password decides both the encryption key and the relay topic, so
  // nothing about it is stored and only the right password finds the room.
  async function deriveRoom(password) {
    const base = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: encoder.encode(SALT), iterations: ITERATIONS },
      base,
      512,
    ));
    const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    const hex = [...bits.slice(32)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
    return { key, topic: `c${hex.slice(0, 40)}`, code: hex.slice(60, 64) };
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

  function readStored(storageKey, fallback) {
    try {
      return JSON.parse(localStorage.getItem(storageKey)) ?? fallback;
    } catch {
      return fallback;
    }
  }

  function writeStored(storageKey, value) {
    try {
      localStorage.setItem(storageKey, JSON.stringify(value));
    } catch {
      // Storage can be blocked; the page still works without it.
    }
  }

  // The relay only keeps messages for a while, so each device keeps its own
  // encrypted copy of recent ones.
  function saveCopy(item) {
    const storageKey = `calc-saved-${room.topic}`;
    const saved = readStored(storageKey, []);
    saved.push({ id: item.id, message: item.message });
    writeStored(storageKey, saved.slice(-MAX_SAVED));
  }

  function closeGate() {
    $('gate').hidden = true;
    $('gate-input').value = '';
    $('gate-error').textContent = '';
  }

  function clearLog() {
    rows.clear();
    $('dm-log').querySelectorAll('.msg').forEach((row) => row.remove());
    $('dm-empty').hidden = false;
  }

  function addRow(id, message) {
    const row = document.createElement('article');
    row.className = 'msg';
    row.dataset.at = String(message.at);
    if (message.name === $('dm-name').value.trim()) row.classList.add('mine');

    const meta = document.createElement('p');
    meta.className = 'msg-meta';
    const time = new Date(message.at).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
    meta.textContent = `${message.name} · ${time}`;

    const text = document.createElement('p');
    text.className = 'msg-text';
    text.textContent = message.text;
    row.append(meta, text);

    const log = $('dm-log');
    const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
    const later = [...log.querySelectorAll('.msg')].find((other) => Number(other.dataset.at) > message.at);
    log.insertBefore(row, later || null);
    rows.set(id, row);
    $('dm-empty').hidden = true;
    if (atBottom) log.scrollTop = log.scrollHeight;
  }

  async function receive(item, isNew) {
    if (rows.has(item.id)) return;
    try {
      const message = await unseal(JSON.parse(item.message));
      if (typeof message.at !== 'number' || typeof message.name !== 'string' || typeof message.text !== 'string') return;
      addRow(item.id, message);
      if (isNew) saveCopy(item);
    } catch {
      // Anything not encrypted with this password is ignored.
    }
  }

  function startListening() {
    const status = $('dm-status');
    const opened = room;
    for (const item of readStored(`calc-saved-${room.topic}`, [])) {
      queue = queue.then(() => receive(item, false));
    }

    stream = new EventSource(`${RELAY}/${room.topic}/sse?since=all`);
    stream.onopen = () => {
      status.textContent = '';
    };
    stream.onmessage = (event) => {
      const item = JSON.parse(event.data);
      if (item.event !== 'message' || room !== opened) return;
      queue = queue.then(() => receive(item, true));
    };
    stream.onerror = () => {
      status.textContent = 'Reconnecting…';
    };
  }

  function openDm() {
    closeGate();
    $('dm-room').textContent = `Room ${room.code}`;
    $('dm').hidden = false;
    startListening();
    $('dm-text').focus();
  }

  function closeDm() {
    $('dm').hidden = true;
    if (stream) stream.close();
    stream = null;
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
      const body = JSON.stringify(await seal({ at: Date.now(), name, text }));
      if (body.length > MAX_BODY) {
        status.textContent = 'Message is too long. Split it in two.';
        return;
      }
      const response = await fetch(`${RELAY}/${room.topic}`, { method: 'POST', body });
      if (response.status === 429) {
        status.textContent = 'Message limit reached. Try again later.';
      } else if (!response.ok) {
        status.textContent = 'Message not sent. Try again.';
      } else {
        input.value = '';
        status.textContent = '';
      }
    } catch {
      status.textContent = 'Message not sent. Check your connection.';
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

    const password = $('gate-input').value;
    if (password.length < MIN_PASSWORD) {
      $('gate-error').textContent = `Use at least ${MIN_PASSWORD} characters.`;
      $('gate-input').select();
      return;
    }

    busy = true;
    try {
      room = await deriveRoom(password);
      openDm();
    } catch {
      $('gate-error').textContent = 'Could not open this. Try again.';
    } finally {
      busy = false;
    }
  });

  $('dm-name').value = readStored(NAME_KEY, '');
  $('dm-name').addEventListener('change', () => writeStored(NAME_KEY, $('dm-name').value.trim()));

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
