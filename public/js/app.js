const PVCrypto = window.PassVaultCrypto;
const deriveAuthProofFn = PVCrypto.deriveAuthProof;
const deriveEncKeyFn = PVCrypto.deriveEncKey;
const encryptVaultFn = PVCrypto.encryptVault;
const decryptVaultFn = PVCrypto.decryptVault;
const randomSaltB64Fn = PVCrypto.randomSaltB64;

let encKey = null;       // lives only in memory, cleared on logout/refresh
let vault = { entries: [] };
let saveTimer = null;
let dirty = false;

const authView = document.getElementById('auth-view');
const vaultView = document.getElementById('vault-view');
const authForm = document.getElementById('auth-form');
const authError = document.getElementById('auth-error');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('master-password');
const modeToggle = document.getElementById('mode-toggle');
const entriesEl = document.getElementById('entries');
const addEntryBtn = document.getElementById('add-entry');
const logoutBtn = document.getElementById('logout');
const currentUserEl = document.getElementById('current-user');
const saveStatusEl = document.getElementById('save-status');
const srStatusEl = document.getElementById('sr-status');
function announce(text) { srStatusEl.textContent = text; }
const pwStrengthEl = document.getElementById('pw-strength');
const pwStrengthFill = document.getElementById('pw-strength-fill');
const pwStrengthLabel = document.getElementById('pw-strength-label');

let mode = 'login'; // or 'register'

modeToggle.addEventListener('click', () => {
  mode = mode === 'login' ? 'register' : 'login';
  document.getElementById('auth-title').textContent = mode === 'login' ? 'Log in' : 'Create account';
  document.getElementById('auth-submit').textContent = mode === 'login' ? 'Log in' : 'Create account';
  modeToggle.textContent = mode === 'login' ? "Need an account? Register" : 'Already have an account? Log in';
  authError.textContent = '';
  pwStrengthEl.classList.add('hidden');
});

// Rough client-side strength heuristic — just enough to steer people away
// from a weak master password, which can't be recovered if forgotten.
function estimatePasswordStrength(pw) {
  const variety = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(re => re.test(pw)).length;
  const lengthScore = Math.min(pw.length / 20, 1);
  const score = lengthScore * 0.7 + (variety / 4) * 0.3;
  if (pw.length < 8) return { label: 'Too short', score: 0.08, level: '' };
  if (score < 0.4) return { label: 'Weak', score, level: '' };
  if (score < 0.65) return { label: 'Fair', score, level: 'fair' };
  if (score < 0.85) return { label: 'Good', score, level: 'good' };
  return { label: 'Strong', score, level: 'strong' };
}

passwordInput.addEventListener('input', () => {
  if (mode !== 'register') return;
  const pw = passwordInput.value;
  if (!pw) { pwStrengthEl.classList.add('hidden'); return; }
  pwStrengthEl.classList.remove('hidden');
  const { label, score, level } = estimatePasswordStrength(pw);
  pwStrengthFill.style.width = Math.round(score * 100) + '%';
  pwStrengthFill.className = 'pw-strength-fill' + (level ? ' ' + level : '');
  pwStrengthLabel.textContent = 'Master password strength: ' + label;
});

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  authError.textContent = '';
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) return;
  if (mode === 'register' && password.length < 8) {
    authError.textContent = 'Master password should be at least 8 characters — this is the ONE password you must never forget.';
    return;
  }
  try {
    if (mode === 'register') {
      const salt = randomSaltB64Fn();
      const authProof = await deriveAuthProofFn(password, salt);
      await Api.register(username, salt, authProof);
      await Api.login(username, authProof); // establish the server session
      encKey = await deriveEncKeyFn(password, salt);
    } else {
      const { salt } = await Api.getSalt(username);
      const authProof = await deriveAuthProofFn(password, salt);
      await Api.login(username, authProof);
      encKey = await deriveEncKeyFn(password, salt);
    }
    passwordInput.value = '';
    pwStrengthEl.classList.add('hidden');
    await enterVault(username);
  } catch (err) {
    authError.textContent = err.message || 'Something went wrong.';
  }
});

logoutBtn.addEventListener('click', async () => {
  clearTimeout(saveTimer);
  if (dirty) await saveVaultNow(); // flush any pending debounced save first
  await Api.logout();
  encKey = null;
  vault = { entries: [] };
  vaultView.classList.add('hidden');
  authView.classList.remove('hidden');
  authForm.reset();
});

async function enterVault(username) {
  currentUserEl.textContent = username;
  const stored = await Api.getVault();
  if (stored.blob) {
    try {
      vault = await decryptVaultFn(stored, encKey);
    } catch (e) {
      authError.textContent = 'Could not decrypt vault — wrong master password?';
      encKey = null;
      return;
    }
  } else {
    vault = { entries: [] };
  }
  if (!vault.entries) vault.entries = [];
  authView.classList.add('hidden');
  vaultView.classList.remove('hidden');
  renderEntries();
}

function newEntry() {
  return {
    id: crypto.randomUUID(),
    email: '',
    username: '',
    passwords: [{ label: 'Password 1', value: '' }],
    keyQuestions: []
  };
}

function renderEntries() {
  entriesEl.innerHTML = '';
  vault.entries.forEach((entry, idx) => {
    entriesEl.appendChild(renderEntry(entry, idx));
  });
}

function renderEntry(entry, idx) {
  const card = document.createElement('div');
  card.className = 'entry-card';

  // Header: editable email address
  const header = document.createElement('div');
  header.className = 'entry-header';
  const emailInput = document.createElement('input');
  emailInput.type = 'text';
  emailInput.placeholder = 'Email address (this is the header)';
  emailInput.setAttribute('aria-label', 'Email address (section header)');
  emailInput.autocomplete = 'off';
  emailInput.value = entry.email;
  emailInput.className = 'email-input';
  emailInput.addEventListener('input', () => { entry.email = emailInput.value; markDirty(); });
  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = 'Remove this section';
  removeBtn.setAttribute('aria-label', 'Remove section for ' + (entry.email || 'this entry'));
  removeBtn.addEventListener('click', () => {
    if (confirm('Remove this section for ' + (entry.email || '(no email)') + '? This cannot be undone.')) {
      vault.entries.splice(idx, 1);
      markDirty();
      renderEntries();
    }
  });
  header.appendChild(emailInput);
  header.appendChild(removeBtn);
  card.appendChild(header);

  const body = document.createElement('div');
  body.className = 'entry-body';

  // Username
  const userLabel = document.createElement('label');
  userLabel.textContent = 'Username';
  userLabel.htmlFor = 'username-' + entry.id;
  const userInput = document.createElement('input');
  userInput.type = 'text';
  userInput.id = 'username-' + entry.id;
  userInput.autocomplete = 'off';
  userInput.value = entry.username;
  userInput.addEventListener('input', () => { entry.username = userInput.value; markDirty(); });
  body.appendChild(userLabel);
  body.appendChild(userInput);

  // Passwords (up to 5)
  const pwSection = document.createElement('div');
  pwSection.className = 'sub-section';
  const pwTitle = document.createElement('div');
  pwTitle.className = 'sub-title';
  pwTitle.textContent = 'Passwords (up to 5)';
  pwSection.appendChild(pwTitle);

  const pwList = document.createElement('div');
  entry.passwords.forEach((pw, pwIdx) => {
    pwList.appendChild(renderPasswordRow(entry, pw, pwIdx));
  });
  pwSection.appendChild(pwList);

  const addPwBtn = document.createElement('button');
  addPwBtn.className = 'link-btn';
  addPwBtn.textContent = '+ Add password';
  addPwBtn.addEventListener('click', () => {
    if (entry.passwords.length >= 5) return;
    entry.passwords.push({ label: 'Password ' + (entry.passwords.length + 1), value: '' });
    markDirty();
    renderEntries();
  });
  if (entry.passwords.length >= 5) addPwBtn.disabled = true;
  pwSection.appendChild(addPwBtn);
  body.appendChild(pwSection);

  // Key Questions
  const kqSection = document.createElement('div');
  kqSection.className = 'sub-section';
  const kqTitle = document.createElement('div');
  kqTitle.className = 'sub-title';
  kqTitle.textContent = 'Key Questions';
  kqSection.appendChild(kqTitle);

  entry.keyQuestions.forEach((kq, kqIdx) => {
    kqSection.appendChild(renderKeyQuestionRow(entry, kq, kqIdx));
  });

  const addKqBtn = document.createElement('button');
  addKqBtn.className = 'link-btn';
  addKqBtn.textContent = '+ Add key question';
  addKqBtn.addEventListener('click', () => {
    entry.keyQuestions.push({ question: '', answer: '' });
    markDirty();
    renderEntries();
  });
  kqSection.appendChild(addKqBtn);
  body.appendChild(kqSection);

  card.appendChild(body);
  return card;
}

function clearClipboardAfter(expectedValue, delayMs) {
  setTimeout(async () => {
    try {
      const current = await navigator.clipboard.readText();
      if (current === expectedValue) {
        await navigator.clipboard.writeText('');
      }
    } catch (e) {
      // Clipboard read permission denied or unavailable — nothing we can do.
    }
  }, delayMs);
}

function renderPasswordRow(entry, pw, pwIdx) {
  const row = document.createElement('div');
  row.className = 'pw-row';

  const labelInput = document.createElement('input');
  labelInput.type = 'text';
  labelInput.className = 'pw-label';
  labelInput.setAttribute('aria-label', 'Label for password ' + (pwIdx + 1));
  labelInput.autocomplete = 'off';
  labelInput.value = pw.label || ('Password ' + (pwIdx + 1));
  labelInput.addEventListener('input', () => { pw.label = labelInput.value; markDirty(); });

  const valueInput = document.createElement('input');
  valueInput.type = 'password';
  valueInput.className = 'pw-value';
  valueInput.setAttribute('aria-label', (pw.label || ('Password ' + (pwIdx + 1))) + ' value');
  valueInput.autocomplete = 'off';
  valueInput.value = pw.value;
  valueInput.placeholder = 'Password';
  valueInput.addEventListener('input', () => { pw.value = valueInput.value; markDirty(); });

  const toggleBtn = document.createElement('button');
  toggleBtn.className = 'icon-btn';
  toggleBtn.textContent = '👁';
  toggleBtn.title = 'Show/hide';
  toggleBtn.setAttribute('aria-label', 'Show password');
  toggleBtn.setAttribute('aria-pressed', 'false');
  toggleBtn.addEventListener('click', () => {
    const nowVisible = valueInput.type === 'password';
    valueInput.type = nowVisible ? 'text' : 'password';
    toggleBtn.setAttribute('aria-label', nowVisible ? 'Hide password' : 'Show password');
    toggleBtn.setAttribute('aria-pressed', String(nowVisible));
  });

  const copyBtn = document.createElement('button');
  copyBtn.className = 'icon-btn';
  copyBtn.textContent = '📋';
  copyBtn.title = 'Copy password';
  copyBtn.setAttribute('aria-label', 'Copy password to clipboard');
  copyBtn.addEventListener('click', async () => {
    if (!pw.value) return;
    const copiedValue = pw.value;
    try {
      await navigator.clipboard.writeText(copiedValue);
    } catch (e) {
      // Fallback for browsers/contexts without Clipboard API access
      const tmp = document.createElement('textarea');
      tmp.value = copiedValue;
      tmp.style.position = 'fixed';
      tmp.style.opacity = '0';
      document.body.appendChild(tmp);
      tmp.select();
      document.execCommand('copy');
      document.body.removeChild(tmp);
    }
    const original = copyBtn.textContent;
    copyBtn.textContent = '✅';
    setTimeout(() => { copyBtn.textContent = original; }, 1200);
    announce('Password copied to clipboard. It will clear automatically in 20 seconds.');
    // Clear the clipboard after a delay, but only if it still holds
    // what we put there (avoid clobbering something the user copied since).
    clearClipboardAfter(copiedValue, 20000);
  });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = 'Remove this password';
  removeBtn.setAttribute('aria-label', 'Remove ' + (pw.label || ('password ' + (pwIdx + 1))));
  removeBtn.addEventListener('click', () => {
    entry.passwords.splice(pwIdx, 1);
    markDirty();
    renderEntries();
  });

  row.appendChild(labelInput);
  row.appendChild(valueInput);
  row.appendChild(toggleBtn);
  row.appendChild(copyBtn);
  row.appendChild(removeBtn);
  return row;
}

function renderKeyQuestionRow(entry, kq, kqIdx) {
  const row = document.createElement('div');
  row.className = 'kq-row';

  const qInput = document.createElement('input');
  qInput.type = 'text';
  qInput.placeholder = 'Question (e.g. Mother\'s maiden name)';
  qInput.setAttribute('aria-label', 'Security question ' + (kqIdx + 1));
  qInput.autocomplete = 'off';
  qInput.value = kq.question;
  qInput.addEventListener('input', () => { kq.question = qInput.value; markDirty(); });

  const aInput = document.createElement('input');
  aInput.type = 'text';
  aInput.placeholder = 'Answer';
  aInput.setAttribute('aria-label', 'Answer to security question ' + (kqIdx + 1));
  aInput.autocomplete = 'off';
  aInput.value = kq.answer;
  aInput.addEventListener('input', () => { kq.answer = aInput.value; markDirty(); });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = 'Remove this key question';
  removeBtn.setAttribute('aria-label', 'Remove security question ' + (kqIdx + 1));
  removeBtn.addEventListener('click', () => {
    entry.keyQuestions.splice(kqIdx, 1);
    markDirty();
    renderEntries();
  });

  row.appendChild(qInput);
  row.appendChild(aInput);
  row.appendChild(removeBtn);
  return row;
}

addEntryBtn.addEventListener('click', () => {
  vault.entries.unshift(newEntry());
  markDirty();
  renderEntries();
});

function markDirty() {
  dirty = true;
  saveStatusEl.textContent = 'Unsaved changes…';
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveVaultNow, 1200);
}

async function saveVaultNow() {
  if (!dirty || !encKey) return;
  try {
    saveStatusEl.textContent = 'Saving…';
    const { iv, blob } = await encryptVaultFn(vault, encKey);
    await Api.saveVault(iv, blob);
    dirty = false;
    saveStatusEl.textContent = 'Saved';
    setTimeout(() => { if (!dirty) saveStatusEl.textContent = ''; }, 1500);
  } catch (e) {
    saveStatusEl.textContent = 'Save failed — check connection';
  }
}

window.addEventListener('beforeunload', (e) => {
  if (dirty) {
    saveVaultNow();
    e.preventDefault();
    e.returnValue = '';
  }
});

// On load, check if there's an active server session. Note: even if
// the session cookie is valid, we still need the master password to
// derive encKey and decrypt the vault, so we always show the login
// form unless we already have encKey in memory (we never do, on a
// fresh page load, since it's never persisted).
(async () => {
  const { loggedIn } = await Api.me();
  if (loggedIn) {
    // Server thinks we're logged in, but we lost encKey on refresh.
    // Force re-entry of the master password before showing any data.
    await Api.logout();
  }
})();
