'use strict';

const META_KEY = 'privateDailyVaultMetaV1';
const DB_NAME = 'privateDailyVaultDB';
const STORE = 'vaultStore';
const VERIFIER = 'PRIVATE_DAILY_VAULT_OK';

let cryptoKey = null;
let appData = { notes: [] };
let statusTimer;

const $ = selector => document.querySelector(selector);
const setupView = $('#setupView');
const unlockView = $('#unlockView');
const appView = $('#appView');

function bytesToB64(bytes) {
  let value = '';
  bytes.forEach(byte => { value += String.fromCharCode(byte); });
  return btoa(value);
}

function b64ToBytes(value) {
  const decoded = atob(value);
  return Uint8Array.from(decoded, char => char.charCodeAt(0));
}

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function show(view) {
  [setupView, unlockView, appView].forEach(item => item.classList.add('hidden'));
  view.classList.remove('hidden');
}

function toast(message) {
  const element = $('#status');
  element.textContent = message;
  element.classList.remove('hidden');
  clearTimeout(statusTimer);
  statusTimer = setTimeout(() => element.classList.add('hidden'), 2200);
}

function today() {
  return new Date().toLocaleDateString('en-CA');
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[char]));
}

function uid() {
  return crypto.randomUUID
    ? crypto.randomUUID()
    : Date.now().toString(36) + Math.random().toString(36).slice(2);
}

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) {
        request.result.createObjectStore(STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbGet(key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const request = tx.objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => db.close();
  });
}

async function dbSet(key, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(value, key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  });
}

async function dbClear() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).clear();
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => reject(tx.error);
  });
}

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptValue(value, key) {
  const iv = randomBytes(12);
  const plain = new TextEncoder().encode(JSON.stringify(value));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
  return {
    iv: bytesToB64(iv),
    data: bytesToB64(new Uint8Array(encrypted))
  };
}

async function decryptValue(payload, key) {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(payload.iv) },
    key,
    b64ToBytes(payload.data)
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}

async function saveVault() {
  if (!cryptoKey) throw new Error('Vault is locked');
  await dbSet('vault', await encryptValue(appData, cryptoKey));
}

function initialize() {
  if (!window.isSecureContext || !crypto.subtle) {
    show(setupView);
    toast('請使用 HTTPS 網址開啟此 App');
    return;
  }

  if (navigator.storage?.persist) {
    navigator.storage.persist().catch(() => {});
  }

  show(localStorage.getItem(META_KEY) ? unlockView : setupView);
}

$('#setupForm').addEventListener('submit', async event => {
  event.preventDefault();
  const password = $('#newPassword').value;
  const confirmation = $('#confirmPassword').value;

  if (password !== confirmation) return toast('兩次密碼不一致');
  if (password.length < 6) return toast('密碼最少需要 6 個字元');

  try {
    const salt = randomBytes(16);
    cryptoKey = await deriveKey(password, salt);
    const verifier = await encryptValue(VERIFIER, cryptoKey);
    localStorage.setItem(META_KEY, JSON.stringify({
      version: 1,
      salt: bytesToB64(salt),
      verifier
    }));
    appData = { notes: [] };
    await saveVault();
    event.target.reset();
    show(appView);
    render();
    toast('私人記錄庫已建立');
  } catch (error) {
    console.error(error);
    toast('建立失敗，請再試一次');
  }
});

$('#unlockForm').addEventListener('submit', async event => {
  event.preventDefault();

  try {
    const meta = JSON.parse(localStorage.getItem(META_KEY));
    const candidate = await deriveKey(
      $('#unlockPassword').value,
      b64ToBytes(meta.salt)
    );
    const check = await decryptValue(meta.verifier, candidate);
    if (check !== VERIFIER) throw new Error('Incorrect password');

    const vault = await dbGet('vault');
    appData = vault ? await decryptValue(vault, candidate) : { notes: [] };
    if (!Array.isArray(appData.notes)) appData.notes = [];
    cryptoKey = candidate;
    event.target.reset();
    show(appView);
    render();
    toast('已解鎖');
  } catch (error) {
    console.warn(error);
    toast('密碼錯誤或資料損壞');
  }
});

function closeEditor() {
  if ($('#editorDialog').open) $('#editorDialog').close();
  $('#editorForm').reset();
}

function lock(silent = false) {
  cryptoKey = null;
  appData = { notes: [] };
  $('#searchInput').value = '';
  closeEditor();
  show(unlockView);
  if (!silent) toast('已鎖定');
}

$('#lockBtn').addEventListener('click', () => lock());

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden' && !appView.classList.contains('hidden')) {
    lock(true);
  }
});

window.addEventListener('pageshow', () => {
  if (!cryptoKey && !appView.classList.contains('hidden')) lock(true);
});

function render() {
  const query = $('#searchInput').value.trim().toLowerCase();
  const notes = [...appData.notes].sort((a, b) =>
    String(b.updatedAt || '').localeCompare(String(a.updatedAt || ''))
  );
  const filtered = notes.filter(note =>
    [note.title, note.category, note.content, note.date]
      .join(' ')
      .toLowerCase()
      .includes(query)
  );

  $('#recordCount').textContent = `${appData.notes.length} 項記錄`;
  const list = $('#notesList');

  if (!filtered.length) {
    list.innerHTML = `<div class="card empty">${
      query ? '找不到符合嘅記錄' : '暫時未有記錄，按「新增記錄」開始。'
    }</div>`;
    return;
  }

  list.innerHTML = filtered.map(note => `
    <article class="note">
      <div class="row between" style="align-items:flex-start">
        <div class="grow">
          <h3>${escapeHtml(note.title)}</h3>
          <div class="muted small">
            ${escapeHtml(note.date || '')}
            ${note.category ? `<span class="tag">${escapeHtml(note.category)}</span>` : ''}
          </div>
        </div>
        <div class="row">
          <button class="ghost edit-btn" data-id="${escapeHtml(note.id)}">編輯</button>
          <button class="ghost delete-btn" data-id="${escapeHtml(note.id)}" style="color:#991b1b">刪除</button>
        </div>
      </div>
      <p class="note-text">${escapeHtml(note.content)}</p>
    </article>
  `).join('');
}

$('#searchInput').addEventListener('input', render);

function openEditor(note = null) {
  $('#editorHeading').textContent = note ? '編輯記錄' : '新增記錄';
  $('#editId').value = note?.id || '';
  $('#noteDate').value = note?.date || today();
  $('#noteTitle').value = note?.title || '';
  $('#noteCategory').value = note?.category || '';
  $('#noteContent').value = note?.content || '';
  $('#editorDialog').showModal();
  setTimeout(() => $('#noteTitle').focus(), 50);
}

$('#newBtn').addEventListener('click', () => openEditor());
$('#closeEditor').addEventListener('click', closeEditor);
$('#cancelEditor').addEventListener('click', closeEditor);
$('#editorDialog').addEventListener('click', event => {
  if (event.target === $('#editorDialog')) closeEditor();
});

$('#editorForm').addEventListener('submit', async event => {
  event.preventDefault();
  const id = $('#editId').value || uid();
  const now = new Date().toISOString();
  const oldNote = appData.notes.find(note => note.id === id);
  const note = {
    id,
    date: $('#noteDate').value,
    title: $('#noteTitle').value.trim(),
    category: $('#noteCategory').value.trim(),
    content: $('#noteContent').value.trim(),
    createdAt: oldNote?.createdAt || now,
    updatedAt: now
  };

  if (oldNote) {
    appData.notes = appData.notes.map(item => item.id === id ? note : item);
  } else {
    appData.notes.push(note);
  }

  try {
    await saveVault();
    closeEditor();
    render();
    toast('已加密儲存');
  } catch (error) {
    console.error(error);
    toast('儲存失敗，請重新解鎖');
  }
});

$('#notesList').addEventListener('click', async event => {
  const editButton = event.target.closest('.edit-btn');
  const deleteButton = event.target.closest('.delete-btn');

  if (editButton) {
    const note = appData.notes.find(item => item.id === editButton.dataset.id);
    if (note) openEditor(note);
  }

  if (deleteButton) {
    const note = appData.notes.find(item => item.id === deleteButton.dataset.id);
    if (note && confirm(`確定刪除「${note.title}」？`)) {
      appData.notes = appData.notes.filter(item => item.id !== note.id);
      await saveVault();
      render();
      toast('記錄已刪除');
    }
  }
});

$('#exportBtn').addEventListener('click', async () => {
  try {
    const backup = {
      app: 'private-daily-vault',
      exportedAt: new Date().toISOString(),
      meta: JSON.parse(localStorage.getItem(META_KEY)),
      vault: await dbGet('vault')
    };
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `private-records-backup-${today()}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast('加密備份已匯出');
  } catch (error) {
    console.error(error);
    toast('備份失敗');
  }
});

$('#importInput').addEventListener('change', async event => {
  const file = event.target.files[0];
  if (!file) return;

  try {
    const backup = JSON.parse(await file.text());
    if (
      backup.app !== 'private-daily-vault' ||
      !backup.meta?.salt ||
      !backup.meta?.verifier ||
      !backup.vault?.iv ||
      !backup.vault?.data
    ) throw new Error('Invalid backup');

    if (!confirm('匯入會覆蓋目前裝置內所有記錄，確定繼續？')) {
      event.target.value = '';
      return;
    }

    localStorage.setItem(META_KEY, JSON.stringify(backup.meta));
    await dbSet('vault', backup.vault);
    event.target.value = '';
    lock(true);
    toast('備份已匯入，請用原本密碼解鎖');
  } catch (error) {
    console.error(error);
    event.target.value = '';
    toast('備份檔案格式不正確');
  }
});

$('#resetBtn').addEventListener('click', async () => {
  const answer = prompt('此操作不可復原。請輸入「刪除全部」確認：');
  if (answer !== '刪除全部') return toast('已取消');

  await dbClear();
  localStorage.removeItem(META_KEY);
  cryptoKey = null;
  appData = { notes: [] };
  show(setupView);
  toast('所有本機資料已清除');
});

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(console.warn);
  });
}

initialize();
