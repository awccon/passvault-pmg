const PVCrypto = window.PassVaultCrypto;
const deriveAuthProofFn = PVCrypto.deriveAuthProof;
const deriveEncKeyFn = PVCrypto.deriveEncKey;
const encryptVaultFn = PVCrypto.encryptVault;
const decryptVaultFn = PVCrypto.decryptVault;
const randomSaltB64Fn = PVCrypto.randomSaltB64;
const generatePasswordFn = PVCrypto.generatePassword;

let encKey = null;       // lives only in memory, cleared on logout/refresh
let vault = { entries: [], budget: { expenses: [] } };
let saveTimer = null;
let dirty = false;

const authView = document.getElementById('auth-view');
const vaultView = document.getElementById('vault-view');
const authForm = document.getElementById('auth-form');
const authError = document.getElementById('auth-error');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('master-password');
const inviteCodeField = document.getElementById('invite-code-field');
const inviteCodeInput = document.getElementById('invite-code');
const modeToggle = document.getElementById('mode-toggle');
const entriesEl = document.getElementById('entries');
const addEntryBtn = document.getElementById('add-entry');
const generatorToggle = document.getElementById('generator-toggle');
const generatorBody = document.getElementById('generator-body');
const generatorOutput = document.getElementById('generator-output');
const generatorRegenerateBtn = document.getElementById('generator-regenerate');
const generatorCopyBtn = document.getElementById('generator-copy');
const generatorLengthInput = document.getElementById('generator-length');
const generatorLengthValue = document.getElementById('generator-length-value');
const optUpper = document.getElementById('opt-upper');
const optLower = document.getElementById('opt-lower');
const optNumbers = document.getElementById('opt-numbers');
const optSymbols = document.getElementById('opt-symbols');
const generatorWarning = document.getElementById('generator-warning');
const logoutBtn = document.getElementById('logout');
const changePasswordBtn = document.getElementById('change-password-btn');
const changePasswordDialog = document.getElementById('change-password-dialog');
const changePasswordForm = document.getElementById('change-password-form');
const cpCurrentInput = document.getElementById('cp-current');
const cpNewInput = document.getElementById('cp-new');
const cpConfirmInput = document.getElementById('cp-confirm');
const cpError = document.getElementById('cp-error');
const cpSubmitBtn = document.getElementById('cp-submit');
const cpCancelBtn = document.getElementById('cp-cancel');
const cpStrengthEl = document.getElementById('cp-strength');
const cpStrengthFill = document.getElementById('cp-strength-fill');
const cpStrengthLabel = document.getElementById('cp-strength-label');
const backupBtn = document.getElementById('backup-btn');
const restoreBtn = document.getElementById('restore-btn');
const restoreFileInput = document.getElementById('restore-file-input');
const restoreDialog = document.getElementById('restore-dialog');
const restoreForm = document.getElementById('restore-form');
const restoreFileInfoEl = document.getElementById('restore-file-info');
const restorePasswordInput = document.getElementById('restore-password');
const restoreError = document.getElementById('restore-error');
const restoreSubmitBtn = document.getElementById('restore-submit');
const restoreCancelBtn = document.getElementById('restore-cancel');
const tabVaultBtn = document.getElementById('tab-vault');
const tabBudgetBtn = document.getElementById('tab-budget');
const tabChatBtn = document.getElementById('tab-chat');
const tabAdminBtn = document.getElementById('tab-admin');
const vaultPanel = document.getElementById('vault-panel');
const budgetPanel = document.getElementById('budget-panel');
const chatPanel = document.getElementById('chat-panel');
const adminPanel = document.getElementById('admin-panel');
const adminUsersEl = document.getElementById('admin-users');
const adminMessageCountEl = document.getElementById('admin-message-count');
const clearChatBtn = document.getElementById('clear-chat-btn');
const adminActivityEl = document.getElementById('admin-activity');
const addExpenseBtn = document.getElementById('add-expense');
const expensesEl = document.getElementById('expenses');
const budgetTotalEl = document.getElementById('budget-total');
const budgetBreakdownEl = document.getElementById('budget-breakdown');
const chatMessagesEl = document.getElementById('chat-messages');
const chatForm = document.getElementById('chat-form');
const chatInput = document.getElementById('chat-input');
const currentUserEl = document.getElementById('current-user');
const saveStatusEl = document.getElementById('save-status');
const srStatusEl = document.getElementById('sr-status');
function announce(text) { srStatusEl.textContent = text; }
const pwStrengthEl = document.getElementById('pw-strength');
const pwStrengthFill = document.getElementById('pw-strength-fill');
const pwStrengthLabel = document.getElementById('pw-strength-label');

let mode = 'login'; // or 'register'

let chatMessages = [];
let lastMessageTime = null;
let chatLoaded = false;
let chatPollTimer = null;

let isAdmin = false;
let pendingRestore = null; // parsed+validated backup file, waiting on the password prompt

// Shared by the standalone generator panel and each row's quick-generate
// button, so both honor whatever length/character settings were last set.
let generatorOptions = { length: 20, upper: true, lower: true, numbers: true, symbols: true };

function refreshGeneratorOptions() {
  generatorOptions = {
    length: parseInt(generatorLengthInput.value, 10) || 20,
    upper: optUpper.checked,
    lower: optLower.checked,
    numbers: optNumbers.checked,
    symbols: optSymbols.checked
  };
}

function regenerateOutput() {
  refreshGeneratorOptions();
  generatorLengthValue.textContent = generatorOptions.length;
  const anySelected = generatorOptions.upper || generatorOptions.lower || generatorOptions.numbers || generatorOptions.symbols;
  generatorWarning.classList.toggle('hidden', anySelected);
  generatorOutput.value = anySelected ? generatePasswordFn(generatorOptions.length, generatorOptions) : '';
}

generatorToggle.addEventListener('click', () => {
  const expanded = generatorToggle.getAttribute('aria-expanded') === 'true';
  generatorToggle.setAttribute('aria-expanded', String(!expanded));
  generatorBody.classList.toggle('hidden', expanded);
  if (!expanded && !generatorOutput.value) regenerateOutput();
});
generatorRegenerateBtn.addEventListener('click', regenerateOutput);
generatorLengthInput.addEventListener('input', regenerateOutput);
[optUpper, optLower, optNumbers, optSymbols].forEach(cb => cb.addEventListener('change', regenerateOutput));

generatorCopyBtn.addEventListener('click', async () => {
  if (!generatorOutput.value) return;
  const value = generatorOutput.value;
  try {
    await navigator.clipboard.writeText(value);
  } catch (e) {
    generatorOutput.select();
    document.execCommand('copy');
  }
  announce('Generated password copied to clipboard. It will clear automatically in 20 seconds.');
  clearClipboardAfter(value, 20000);
});

modeToggle.addEventListener('click', () => {
  mode = mode === 'login' ? 'register' : 'login';
  document.getElementById('auth-title').textContent = mode === 'login' ? 'Log in' : 'Create account';
  document.getElementById('auth-submit').textContent = mode === 'login' ? 'Log in' : 'Create account';
  modeToggle.textContent = mode === 'login' ? "Need an account? Register" : 'Already have an account? Log in';
  authError.textContent = '';
  pwStrengthEl.classList.add('hidden');
  inviteCodeField.classList.toggle('hidden', mode !== 'register');
  inviteCodeInput.required = mode === 'register';
  if (mode !== 'register') inviteCodeInput.value = '';
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

function updateStrengthMeter(pw, containerEl, fillEl, labelEl) {
  if (!pw) { containerEl.classList.add('hidden'); return; }
  containerEl.classList.remove('hidden');
  const { label, score, level } = estimatePasswordStrength(pw);
  fillEl.style.width = Math.round(score * 100) + '%';
  fillEl.className = 'pw-strength-fill' + (level ? ' ' + level : '');
  labelEl.textContent = 'Master password strength: ' + label;
}

passwordInput.addEventListener('input', () => {
  if (mode !== 'register') return;
  updateStrengthMeter(passwordInput.value, pwStrengthEl, pwStrengthFill, pwStrengthLabel);
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
      const inviteCode = inviteCodeInput.value.trim();
      const salt = randomSaltB64Fn();
      const authProof = await deriveAuthProofFn(password, salt);
      await Api.register(username, salt, authProof, inviteCode);
      const loginResult = await Api.login(username, authProof); // establish the server session
      isAdmin = !!loginResult.isAdmin;
      encKey = await deriveEncKeyFn(password, salt);
    } else {
      const { salt } = await Api.getSalt(username);
      const authProof = await deriveAuthProofFn(password, salt);
      const loginResult = await Api.login(username, authProof);
      isAdmin = !!loginResult.isAdmin;
      encKey = await deriveEncKeyFn(password, salt);
    }
    passwordInput.value = '';
    inviteCodeInput.value = '';
    pwStrengthEl.classList.add('hidden');
    await enterVault(username);
  } catch (err) {
    authError.textContent = err.message || 'Something went wrong.';
  }
});

function switchTab(tab) {
  vaultPanel.classList.toggle('hidden', tab !== 'vault');
  budgetPanel.classList.toggle('hidden', tab !== 'budget');
  chatPanel.classList.toggle('hidden', tab !== 'chat');
  adminPanel.classList.toggle('hidden', tab !== 'admin');
  tabVaultBtn.classList.toggle('active', tab === 'vault');
  tabBudgetBtn.classList.toggle('active', tab === 'budget');
  tabChatBtn.classList.toggle('active', tab === 'chat');
  tabAdminBtn.classList.toggle('active', tab === 'admin');
  tabVaultBtn.setAttribute('aria-selected', String(tab === 'vault'));
  tabBudgetBtn.setAttribute('aria-selected', String(tab === 'budget'));
  tabChatBtn.setAttribute('aria-selected', String(tab === 'chat'));
  tabAdminBtn.setAttribute('aria-selected', String(tab === 'admin'));

  if (tab === 'chat') {
    if (!chatLoaded) loadChatHistory();
    startChatPolling();
  } else {
    stopChatPolling();
  }
  if (tab === 'admin') loadAdminData();
}
tabVaultBtn.addEventListener('click', () => switchTab('vault'));
tabBudgetBtn.addEventListener('click', () => switchTab('budget'));
tabChatBtn.addEventListener('click', () => switchTab('chat'));
tabAdminBtn.addEventListener('click', () => switchTab('admin'));

logoutBtn.addEventListener('click', async () => {
  clearTimeout(saveTimer);
  if (dirty) await saveVaultNow(); // flush any pending debounced save first
  await Api.logout();
  encKey = null;
  vault = { entries: [], budget: { expenses: [] } };
  stopChatPolling();
  chatMessages = [];
  lastMessageTime = null;
  chatLoaded = false;
  chatMessagesEl.innerHTML = '';
  isAdmin = false;
  tabAdminBtn.classList.add('hidden');
  vaultView.classList.add('hidden');
  authView.classList.remove('hidden');
  authForm.reset();
});

function resetChangePasswordForm() {
  changePasswordForm.reset();
  cpError.textContent = '';
  cpStrengthEl.classList.add('hidden');
  cpSubmitBtn.disabled = false;
}

changePasswordBtn.addEventListener('click', () => {
  resetChangePasswordForm();
  changePasswordDialog.showModal();
  cpCurrentInput.focus();
});

cpCancelBtn.addEventListener('click', () => {
  changePasswordDialog.close();
});

cpNewInput.addEventListener('input', () => {
  updateStrengthMeter(cpNewInput.value, cpStrengthEl, cpStrengthFill, cpStrengthLabel);
});

changePasswordForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  cpError.textContent = '';
  const currentPassword = cpCurrentInput.value;
  const newPassword = cpNewInput.value;
  const confirmPassword = cpConfirmInput.value;
  if (newPassword.length < 8) {
    cpError.textContent = 'New master password should be at least 8 characters.';
    return;
  }
  if (newPassword !== confirmPassword) {
    cpError.textContent = 'New master password and confirmation don\'t match.';
    return;
  }
  cpSubmitBtn.disabled = true;
  try {
    const username = currentUserEl.textContent;
    const { salt: currentSalt } = await Api.getSalt(username);
    const currentAuthProof = await deriveAuthProofFn(currentPassword, currentSalt);
    const candidateEncKey = await deriveEncKeyFn(currentPassword, currentSalt);

    const stored = await Api.getVault();
    let decryptedVault;
    try {
      decryptedVault = stored.blob ? await decryptVaultFn(stored, candidateEncKey) : vault;
    } catch (err) {
      cpError.textContent = 'Current master password is incorrect.';
      cpSubmitBtn.disabled = false;
      return;
    }

    // Flush any pending autosave (made with the OLD key) before we
    // overwrite the stored vault with one encrypted under the NEW key.
    clearTimeout(saveTimer);
    if (dirty) await saveVaultNow();

    const newSalt = randomSaltB64Fn();
    const newAuthProof = await deriveAuthProofFn(newPassword, newSalt);
    const newEncKey = await deriveEncKeyFn(newPassword, newSalt);
    const { iv, blob } = await encryptVaultFn(decryptedVault, newEncKey);

    await Api.changePassword(currentAuthProof, newSalt, newAuthProof, iv, blob);

    encKey = newEncKey; // future autosaves must use the new key
    changePasswordDialog.close();
    announce('Master password changed.');
  } catch (err) {
    cpError.textContent = err.message || 'Something went wrong.';
  } finally {
    cpSubmitBtn.disabled = false;
  }
});

// --- Backup / Restore ---
// A backup file holds the vault in the exact same encrypted form the
// server stores (salt + iv + AES-256-GCM blob) — never plaintext. That
// also means it's tamper-evident: any edit to the file breaks GCM's
// authentication tag, so a corrupted or modified backup fails to
// decrypt cleanly on restore instead of silently loading bad data.
const BACKUP_APP_ID = 'passvault';
const BACKUP_VERSION = 1;

function downloadJSON(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

backupBtn.addEventListener('click', async () => {
  try {
    clearTimeout(saveTimer);
    if (dirty) await saveVaultNow(); // back up exactly what's saved
    const username = currentUserEl.textContent;
    const { salt } = await Api.getSalt(username);
    const { iv, blob } = await encryptVaultFn(vault, encKey);
    const backupObj = {
      app: BACKUP_APP_ID,
      version: BACKUP_VERSION,
      username,
      exportedAt: new Date().toISOString(),
      salt,
      iv,
      blob
    };
    const dateStr = new Date().toISOString().slice(0, 10);
    downloadJSON(backupObj, 'passvault-backup-' + username + '-' + dateStr + '.json');
    announce('Vault backed up.');
  } catch (err) {
    announce(err.message || 'Backup failed.');
  }
});

restoreBtn.addEventListener('click', () => {
  restoreFileInput.click();
});

restoreFileInput.addEventListener('change', async () => {
  const file = restoreFileInput.files[0];
  restoreFileInput.value = ''; // allow re-selecting the same file later
  if (!file) return;

  let parsed;
  try {
    const text = await file.text();
    parsed = JSON.parse(text);
  } catch (e) {
    alert('That file isn\'t readable JSON — is it a PassVault backup?');
    return;
  }
  if (parsed.app !== BACKUP_APP_ID || parsed.version !== BACKUP_VERSION || !parsed.salt || !parsed.iv || !parsed.blob) {
    alert('That doesn\'t look like a PassVault backup file.');
    return;
  }

  pendingRestore = parsed;
  restoreForm.reset();
  restoreError.textContent = '';
  restoreSubmitBtn.disabled = false;
  const info = 'Backup for "' + parsed.username + '"' +
    (parsed.exportedAt ? ', exported ' + new Date(parsed.exportedAt).toLocaleString() : '') + '.';
  restoreFileInfoEl.textContent = info;
  restoreDialog.showModal();
  restorePasswordInput.focus();
});

restoreCancelBtn.addEventListener('click', () => {
  restoreDialog.close();
  pendingRestore = null;
});

restoreForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  restoreError.textContent = '';
  if (!pendingRestore) return;
  const password = restorePasswordInput.value;
  restoreSubmitBtn.disabled = true;
  try {
    const restoreEncKey = await deriveEncKeyFn(password, pendingRestore.salt);
    let restoredVault;
    try {
      restoredVault = await decryptVaultFn(pendingRestore, restoreEncKey);
    } catch (err) {
      restoreError.textContent = 'Incorrect password, or this backup file is corrupted.';
      restoreSubmitBtn.disabled = false;
      return;
    }
    if (!restoredVault.entries) restoredVault.entries = [];
    if (!restoredVault.budget) restoredVault.budget = { expenses: [] };
    if (!restoredVault.budget.expenses) restoredVault.budget.expenses = [];

    const currentCount = vault.entries.length + ' entries, ' + vault.budget.expenses.length + ' expenses';
    const backupCount = restoredVault.entries.length + ' entries, ' + restoredVault.budget.expenses.length + ' expenses';
    const proceed = confirm(
      'Replace your current vault (' + currentCount + ') with this backup (' + backupCount + ')? This cannot be undone.'
    );
    if (!proceed) {
      restoreSubmitBtn.disabled = false;
      return;
    }

    vault = restoredVault;
    dirty = true;
    await saveVaultNow();
    renderEntries();
    renderExpenses();
    pendingRestore = null;
    restoreDialog.close();
    announce('Vault restored successfully.');
  } catch (err) {
    restoreError.textContent = err.message || 'Something went wrong.';
  } finally {
    restoreSubmitBtn.disabled = false;
  }
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
  if (!vault.budget) vault.budget = { expenses: [] };
  if (!vault.budget.expenses) vault.budget.expenses = [];
  tabAdminBtn.classList.toggle('hidden', !isAdmin);
  authView.classList.add('hidden');
  vaultView.classList.remove('hidden');
  switchTab('vault');
  renderEntries();
  renderExpenses();
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

  const generateBtn = document.createElement('button');
  generateBtn.className = 'icon-btn';
  generateBtn.textContent = '🎲';
  generateBtn.title = 'Generate a random password';
  generateBtn.setAttribute('aria-label', 'Generate a random password for ' + (pw.label || ('password ' + (pwIdx + 1))));
  generateBtn.addEventListener('click', () => {
    const generated = generatePasswordFn(generatorOptions.length, generatorOptions);
    if (!generated) {
      announce('Select at least one character type in the password generator first.');
      return;
    }
    pw.value = generated;
    valueInput.value = generated;
    valueInput.type = 'text'; // reveal it briefly so there's a chance to see what was generated
    toggleBtn.setAttribute('aria-label', 'Hide password');
    toggleBtn.setAttribute('aria-pressed', 'true');
    markDirty();
    announce('Generated a new password for ' + (pw.label || ('password ' + (pwIdx + 1))) + '.');
  });

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
    const label = pw.label || ('Password ' + (pwIdx + 1));
    if (!confirm('Remove "' + label + '"? This cannot be undone.')) return;
    entry.passwords.splice(pwIdx, 1);
    markDirty();
    renderEntries();
  });

  row.appendChild(labelInput);
  row.appendChild(valueInput);
  row.appendChild(generateBtn);
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
    if (!confirm('Remove this security question? This cannot be undone.')) return;
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

// --- Budget ---

function newExpense() {
  return {
    id: crypto.randomUUID(),
    date: new Date().toISOString().slice(0, 10),
    category: '',
    description: '',
    amount: 0
  };
}

function renderExpenses() {
  expensesEl.innerHTML = '';
  const expenses = vault.budget.expenses;
  if (expenses.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'expenses-empty';
    empty.textContent = 'No expenses yet. Click "+ Add expense" to start tracking.';
    expensesEl.appendChild(empty);
  } else {
    expenses.forEach((expense, idx) => {
      expensesEl.appendChild(renderExpenseRow(expense, idx));
    });
  }
  renderBudgetSummary();
}

function renderBudgetSummary() {
  const expenses = vault.budget.expenses;
  const total = expenses.reduce((sum, e) => sum + (Number(e.amount) || 0), 0);
  budgetTotalEl.textContent = total.toFixed(2);

  const byCategory = new Map();
  expenses.forEach(e => {
    const key = (e.category || '').trim() || 'Uncategorized';
    byCategory.set(key, (byCategory.get(key) || 0) + (Number(e.amount) || 0));
  });

  budgetBreakdownEl.innerHTML = '';
  if (byCategory.size === 0) {
    const empty = document.createElement('div');
    empty.className = 'breakdown-empty';
    empty.textContent = 'Nothing to break down yet.';
    budgetBreakdownEl.appendChild(empty);
    return;
  }
  [...byCategory.entries()]
    .sort((a, b) => b[1] - a[1])
    .forEach(([category, amount]) => {
      const row = document.createElement('div');
      row.className = 'breakdown-row';
      const catEl = document.createElement('span');
      catEl.className = 'category';
      catEl.textContent = category;
      const amtEl = document.createElement('span');
      amtEl.className = 'amount';
      amtEl.textContent = amount.toFixed(2);
      row.appendChild(catEl);
      row.appendChild(amtEl);
      budgetBreakdownEl.appendChild(row);
    });
}

function renderExpenseRow(expense, idx) {
  const row = document.createElement('div');
  row.className = 'expense-row';

  const dateInput = document.createElement('input');
  dateInput.type = 'date';
  dateInput.className = 'expense-date';
  dateInput.setAttribute('aria-label', 'Expense date');
  dateInput.value = expense.date || '';
  dateInput.addEventListener('input', () => { expense.date = dateInput.value; markDirty(); });

  const categoryInput = document.createElement('input');
  categoryInput.type = 'text';
  categoryInput.className = 'expense-category';
  categoryInput.placeholder = 'Category';
  categoryInput.setAttribute('aria-label', 'Expense category');
  categoryInput.autocomplete = 'off';
  categoryInput.value = expense.category || '';
  categoryInput.addEventListener('input', () => {
    expense.category = categoryInput.value;
    markDirty();
    renderBudgetSummary();
  });

  const descInput = document.createElement('input');
  descInput.type = 'text';
  descInput.className = 'expense-description';
  descInput.placeholder = 'Description';
  descInput.setAttribute('aria-label', 'Expense description');
  descInput.autocomplete = 'off';
  descInput.value = expense.description || '';
  descInput.addEventListener('input', () => { expense.description = descInput.value; markDirty(); });

  const amountInput = document.createElement('input');
  amountInput.type = 'number';
  amountInput.className = 'expense-amount';
  amountInput.placeholder = '0.00';
  amountInput.step = '0.01';
  amountInput.min = '0';
  amountInput.setAttribute('aria-label', 'Expense amount');
  amountInput.autocomplete = 'off';
  amountInput.value = expense.amount === 0 ? '' : expense.amount;
  amountInput.addEventListener('input', () => {
    expense.amount = parseFloat(amountInput.value) || 0;
    markDirty();
    renderBudgetSummary();
  });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = 'Remove this expense';
  removeBtn.setAttribute('aria-label', 'Remove expense' + (expense.description ? ': ' + expense.description : ' ' + (idx + 1)));
  removeBtn.addEventListener('click', () => {
    vault.budget.expenses.splice(idx, 1);
    markDirty();
    renderExpenses();
  });

  row.appendChild(dateInput);
  row.appendChild(categoryInput);
  row.appendChild(descInput);
  row.appendChild(amountInput);
  row.appendChild(removeBtn);
  return row;
}

addExpenseBtn.addEventListener('click', () => {
  vault.budget.expenses.unshift(newExpense());
  markDirty();
  renderExpenses();
});

// --- Chat (shared, plain text — not part of the encrypted vault) ---

function formatChatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' });
}

function renderChatMessage(m) {
  const div = document.createElement('div');
  div.className = 'chat-message' + (m.username === currentUserEl.textContent ? ' own' : '');
  const meta = document.createElement('div');
  meta.className = 'chat-meta';
  const userEl = document.createElement('span');
  userEl.className = 'chat-username';
  userEl.textContent = m.username;
  const timeEl = document.createElement('span');
  timeEl.className = 'chat-time';
  timeEl.textContent = formatChatTime(m.createdAt);
  meta.appendChild(userEl);
  meta.appendChild(timeEl);
  const textEl = document.createElement('div');
  textEl.className = 'chat-text';
  textEl.textContent = m.text;
  div.appendChild(meta);
  div.appendChild(textEl);
  return div;
}

function renderFullChatHistory() {
  chatMessagesEl.innerHTML = '';
  if (chatMessages.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'chat-empty';
    empty.textContent = 'No messages yet — say hello!';
    chatMessagesEl.appendChild(empty);
  } else {
    chatMessages.forEach(m => chatMessagesEl.appendChild(renderChatMessage(m)));
  }
  chatMessagesEl.scrollTop = chatMessagesEl.scrollHeight;
}

function appendChatMessages(newMessages) {
  const emptyEl = chatMessagesEl.querySelector('.chat-empty');
  if (emptyEl) emptyEl.remove();
  newMessages.forEach(m => chatMessagesEl.appendChild(renderChatMessage(m)));
  chatMessagesEl.scrollTop = chatMessagesEl.scrollHeight;
}

async function loadChatHistory() {
  // Load history with the live region off so a screen reader doesn't
  // announce the whole backlog at once; switch it on for later arrivals.
  chatMessagesEl.setAttribute('aria-live', 'off');
  try {
    const { messages } = await Api.getMessages();
    chatMessages = messages;
    renderFullChatHistory();
    if (messages.length) lastMessageTime = messages[messages.length - 1].createdAt;
  } catch (e) {
    // Leave the panel empty; the next poll will retry.
  }
  chatMessagesEl.setAttribute('aria-live', 'polite');
  chatLoaded = true;
}

async function pollNewMessages() {
  try {
    const { messages } = await Api.getMessages(lastMessageTime);
    if (messages.length) {
      chatMessages = chatMessages.concat(messages);
      lastMessageTime = messages[messages.length - 1].createdAt;
      appendChatMessages(messages);
    }
  } catch (e) {
    // Silent — will retry on the next poll tick.
  }
}

function startChatPolling() {
  stopChatPolling();
  chatPollTimer = setInterval(pollNewMessages, 4000);
}

function stopChatPolling() {
  clearInterval(chatPollTimer);
  chatPollTimer = null;
}

chatForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = chatInput.value.trim();
  if (!text) return;
  chatInput.disabled = true;
  try {
    const { message } = await Api.sendMessage(text);
    chatMessages.push(message);
    lastMessageTime = message.createdAt;
    appendChatMessages([message]);
    chatInput.value = '';
  } catch (err) {
    announce(err.message || 'Failed to send message');
  } finally {
    chatInput.disabled = false;
    chatInput.focus();
  }
});

// --- Admin (only reachable at all if the server granted isAdmin) ---

async function loadAdminData() {
  try {
    const { users, messageCount } = await Api.getAdminUsers();
    renderAdminUsers(users);
    adminMessageCountEl.textContent = messageCount + (messageCount === 1 ? ' message' : ' messages');
  } catch (err) {
    announce(err.message || 'Failed to load admin data.');
  }
  try {
    const { activity } = await Api.getAdminActivity();
    renderAdminActivity(activity);
  } catch (err) {
    announce(err.message || 'Failed to load activity log.');
  }
}

function renderAdminUsers(users) {
  adminUsersEl.innerHTML = '';
  if (users.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'admin-empty';
    empty.textContent = 'No registered users.';
    adminUsersEl.appendChild(empty);
    return;
  }
  users.forEach(u => adminUsersEl.appendChild(renderAdminUserRow(u)));
}

function renderAdminUserRow(u) {
  const row = document.createElement('div');
  row.className = 'admin-user-row';

  const info = document.createElement('div');
  info.className = 'admin-user-info';
  const nameEl = document.createElement('span');
  nameEl.className = 'admin-username';
  nameEl.textContent = u.username;
  const metaEl = document.createElement('span');
  metaEl.className = 'admin-user-meta';
  const joined = new Date(u.createdAt).toLocaleDateString();
  const lastLogin = u.lastLoginAt
    ? 'last login ' + new Date(u.lastLoginAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    : 'never logged in';
  metaEl.textContent = 'Joined ' + joined + ' · ' + lastLogin + (u.hasVaultData ? '' : ' · no vault data yet');
  info.appendChild(nameEl);
  info.appendChild(metaEl);
  row.appendChild(info);

  const isSelf = u.username.toLowerCase() === currentUserEl.textContent.toLowerCase();
  if (isSelf) {
    const badge = document.createElement('span');
    badge.className = 'admin-you-badge';
    badge.textContent = 'You (admin)';
    row.appendChild(badge);
  } else {
    const delBtn = document.createElement('button');
    delBtn.className = 'icon-btn danger';
    delBtn.textContent = '✕';
    delBtn.title = 'Delete this user';
    delBtn.setAttribute('aria-label', 'Delete user ' + u.username);
    delBtn.addEventListener('click', async () => {
      if (!confirm('Permanently delete the account "' + u.username + '" and their vault? This cannot be undone.')) return;
      try {
        await Api.deleteAdminUser(u.id);
        announce('Deleted user ' + u.username + '.');
        loadAdminData();
      } catch (err) {
        announce(err.message || 'Failed to delete user.');
      }
    });
    row.appendChild(delBtn);
  }
  return row;
}

const ACTIVITY_LABELS = {
  login: e => e.username + ' logged in',
  login_failed: e => 'Failed login attempt for "' + e.username + '"',
  register: e => e.username + ' registered',
  user_deleted: e => e.username + ' was deleted by ' + (e.deletedBy || 'admin'),
  chat_cleared: e => 'Chat history cleared by ' + e.username,
  password_changed: e => e.username + ' changed their master password'
};
const ACTIVITY_ICONS = {
  login: '🔓',
  login_failed: '⚠️',
  register: '✨',
  user_deleted: '🗑',
  chat_cleared: '🧹',
  password_changed: '🔑'
};

function renderAdminActivity(activity) {
  adminActivityEl.innerHTML = '';
  if (activity.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'admin-empty';
    empty.textContent = 'No activity recorded yet.';
    adminActivityEl.appendChild(empty);
    return;
  }
  activity.forEach(e => {
    const row = document.createElement('div');
    row.className = 'admin-activity-row' + (e.type === 'login_failed' ? ' warn' : '');
    const textEl = document.createElement('span');
    textEl.className = 'admin-activity-text';
    const label = ACTIVITY_LABELS[e.type] ? ACTIVITY_LABELS[e.type](e) : e.type;
    textEl.textContent = (ACTIVITY_ICONS[e.type] || '•') + ' ' + label;
    const timeEl = document.createElement('span');
    timeEl.className = 'admin-activity-time';
    timeEl.textContent = new Date(e.at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    row.appendChild(textEl);
    row.appendChild(timeEl);
    adminActivityEl.appendChild(row);
  });
}

clearChatBtn.addEventListener('click', async () => {
  if (!confirm('Clear all chat history for everyone? This cannot be undone.')) return;
  try {
    await Api.clearChatHistory();
    chatMessages = [];
    lastMessageTime = null;
    renderFullChatHistory();
    announce('Chat history cleared.');
    loadAdminData();
  } catch (err) {
    announce(err.message || 'Failed to clear chat history.');
  }
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
