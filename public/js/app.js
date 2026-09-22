const t = window.PVI18N.t;
const PVCrypto = window.PassVaultCrypto;
const deriveAuthProofFn = PVCrypto.deriveAuthProof;
const deriveEncKeyFn = PVCrypto.deriveEncKey;
const encryptVaultFn = PVCrypto.encryptVault;
const decryptVaultFn = PVCrypto.decryptVault;
const randomSaltB64Fn = PVCrypto.randomSaltB64;
const generatePasswordFn = PVCrypto.generatePassword;

let encKey = null;       // lives only in memory, cleared on logout/refresh
let vault = { entries: [], budget: { expenses: [], incomes: [] }, notes: [], addresses: [], goals: [], todos: [] };
let saveTimer = null;
let dirty = false;

const authView = document.getElementById('auth-view');
const vaultView = document.getElementById('vault-view');
const authForm = document.getElementById('auth-form');
const authError = document.getElementById('auth-error');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('master-password');
const masterPasswordToggle = document.getElementById('master-password-toggle');
const inviteCodeField = document.getElementById('invite-code-field');
const inviteCodeInput = document.getElementById('invite-code');
const modeToggle = document.getElementById('mode-toggle');
const entriesEl = document.getElementById('entries');
const entriesListEl = document.getElementById('entries-list');
const vaultListView = document.getElementById('vault-list-view');
const vaultDetailView = document.getElementById('vault-detail-view');
const vaultSearchInput = document.getElementById('vault-search');
const vaultBackBtn = document.getElementById('vault-back-btn');
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
const tabMoreBtn = document.getElementById('tab-more');
const vaultPanel = document.getElementById('vault-panel');
const budgetPanel = document.getElementById('budget-panel');
const chatPanel = document.getElementById('chat-panel');
const morePanel = document.getElementById('more-panel');
const themeButtons = document.querySelectorAll('[data-theme-choice]');
const adminSettingsSection = document.getElementById('admin-settings-section');
const adminUsersEl = document.getElementById('admin-users');
const adminMessageCountEl = document.getElementById('admin-message-count');
const clearChatBtn = document.getElementById('clear-chat-btn');
const adminActivityEl = document.getElementById('admin-activity');
const addExpenseBtn = document.getElementById('add-expense');
const expensesEl = document.getElementById('expenses');
const budgetTotalEl = document.getElementById('budget-total');
const addIncomeBtn = document.getElementById('add-income');
const incomesEl = document.getElementById('incomes');
const budgetIncomeTotalEl = document.getElementById('budget-income-total');
const budgetNetEl = document.getElementById('budget-net');
const budgetChartEl = document.getElementById('budget-chart');
const addNoteBtn = document.getElementById('add-note');
const notesListEl = document.getElementById('notes-list');
const addAddressBtn = document.getElementById('add-address');
const addressesListEl = document.getElementById('addresses-list');
const addGoalBtn = document.getElementById('add-goal');
const goalsListEl = document.getElementById('goals-list');
const newTodoInput = document.getElementById('new-todo-input');
const todoListEl = document.getElementById('todo-list');
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

// Password rows default to view-only (show/copy only); editing unlocks
// the label/value fields plus generate/delete. Tracked by password id
// (not array index, which shifts) so it survives the full re-renders
// triggered by unrelated changes elsewhere in the vault.
let editingPasswordIds = new Set();

// Vault is a list view (search + rows) with a detail view for one
// entry at a time. null = showing the list.
let currentEntryId = null;
let vaultSearchQuery = '';

function ensurePasswordIds(entries) {
  entries.forEach(entry => {
    entry.passwords.forEach(pw => {
      if (!pw.id) pw.id = crypto.randomUUID();
    });
  });
}

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
  announce(t('generator.copiedAnnounce'));
  clearClipboardAfter(value, 20000);
});

function updateAuthModeText() {
  document.getElementById('auth-title').textContent = mode === 'login' ? t('auth.login') : t('auth.createAccount');
  document.getElementById('auth-submit').textContent = mode === 'login' ? t('auth.login') : t('auth.createAccount');
  modeToggle.textContent = mode === 'login' ? t('auth.needAccount') : t('auth.haveAccount');
}

modeToggle.addEventListener('click', () => {
  mode = mode === 'login' ? 'register' : 'login';
  updateAuthModeText();
  authError.textContent = '';
  pwStrengthEl.classList.add('hidden');
  passwordInput.type = 'password';
  masterPasswordToggle.setAttribute('aria-label', t('common.showPassword'));
  masterPasswordToggle.setAttribute('aria-pressed', 'false');
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
  if (pw.length < 8) return { label: t('strength.tooShort'), score: 0.08, level: '' };
  if (score < 0.4) return { label: t('strength.weak'), score, level: '' };
  if (score < 0.65) return { label: t('strength.fair'), score, level: 'fair' };
  if (score < 0.85) return { label: t('strength.good'), score, level: 'good' };
  return { label: t('strength.strong'), score, level: 'strong' };
}

function updateStrengthMeter(pw, containerEl, fillEl, labelEl) {
  if (!pw) { containerEl.classList.add('hidden'); return; }
  containerEl.classList.remove('hidden');
  const { label, score, level } = estimatePasswordStrength(pw);
  fillEl.style.width = Math.round(score * 100) + '%';
  fillEl.className = 'pw-strength-fill' + (level ? ' ' + level : '');
  labelEl.textContent = t('strength.prefix', { label });
}

passwordInput.addEventListener('input', () => {
  if (mode !== 'register') return;
  updateStrengthMeter(passwordInput.value, pwStrengthEl, pwStrengthFill, pwStrengthLabel);
});

masterPasswordToggle.addEventListener('click', () => {
  const nowVisible = passwordInput.type === 'password';
  passwordInput.type = nowVisible ? 'text' : 'password';
  masterPasswordToggle.setAttribute('aria-label', nowVisible ? t('common.hidePassword') : t('common.showPassword'));
  masterPasswordToggle.setAttribute('aria-pressed', String(nowVisible));
});

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  authError.textContent = '';
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) return;
  if (mode === 'register' && password.length < 8) {
    authError.textContent = t('auth.pwTooShort');
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
    passwordInput.type = 'password';
    masterPasswordToggle.setAttribute('aria-label', t('common.showPassword'));
    masterPasswordToggle.setAttribute('aria-pressed', 'false');
    inviteCodeInput.value = '';
    pwStrengthEl.classList.add('hidden');
    await enterVault(username);
  } catch (err) {
    authError.textContent = err.message || t('common.somethingWrong');
  }
});

function switchTab(tab) {
  vaultPanel.classList.toggle('hidden', tab !== 'vault');
  budgetPanel.classList.toggle('hidden', tab !== 'budget');
  chatPanel.classList.toggle('hidden', tab !== 'chat');
  const isMore = tab === 'more';
  morePanel.classList.toggle('hidden', !isMore);
  tabVaultBtn.classList.toggle('active', tab === 'vault');
  tabBudgetBtn.classList.toggle('active', tab === 'budget');
  tabChatBtn.classList.toggle('active', tab === 'chat');
  tabMoreBtn.classList.toggle('active', isMore);
  tabVaultBtn.setAttribute('aria-selected', String(tab === 'vault'));
  tabBudgetBtn.setAttribute('aria-selected', String(tab === 'budget'));
  tabChatBtn.setAttribute('aria-selected', String(tab === 'chat'));
  tabMoreBtn.setAttribute('aria-selected', String(isMore));

  if (tab === 'chat') {
    if (!chatLoaded) loadChatHistory();
    startChatPolling();
  } else {
    stopChatPolling();
  }

  // Whichever More sub-page (Settings/Notes/Addresses/Goals/To-Do) might be
  // open, close it whenever a top-level tab is chosen — including
  // re-choosing "More" itself, which should always land back on the hub.
  document.querySelectorAll('.more-subpage').forEach(el => el.classList.add('hidden'));
}
tabVaultBtn.addEventListener('click', () => switchTab('vault'));
tabBudgetBtn.addEventListener('click', () => switchTab('budget'));
tabChatBtn.addEventListener('click', () => switchTab('chat'));
tabMoreBtn.addEventListener('click', () => switchTab('more'));

function openMorePage(panelId) {
  morePanel.classList.add('hidden');
  document.querySelectorAll('.more-subpage').forEach(el => el.classList.toggle('hidden', el.id !== panelId));
  if (panelId === 'settings-panel' && isAdmin) loadAdminData();
}
function closeMorePage() {
  document.querySelectorAll('.more-subpage').forEach(el => el.classList.add('hidden'));
  morePanel.classList.remove('hidden');
}
document.querySelectorAll('#more-panel [data-more-target]').forEach(btn => {
  btn.addEventListener('click', () => openMorePage(btn.getAttribute('data-more-target')));
});
document.querySelectorAll('.more-back-btn').forEach(btn => {
  btn.addEventListener('click', closeMorePage);
});

// --- Theme (light / dark / system) ---
// A per-device UI preference, not vault data — stored in localStorage,
// not the encrypted blob, so it applies even on the login screen.

function resolveEffectiveTheme(mode) {
  if (mode === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return mode;
}

function applyTheme(mode) {
  try { localStorage.setItem('pv-theme', mode); } catch (e) { /* private browsing, etc. — theme just won't persist */ }
  document.documentElement.setAttribute('data-theme', mode);
  const effective = resolveEffectiveTheme(mode);
  const themeColorMeta = document.querySelector('meta[name="theme-color"]');
  if (themeColorMeta) themeColorMeta.setAttribute('content', effective === 'light' ? '#f4f6fb' : '#0f1420');
  themeButtons.forEach(btn => btn.setAttribute('aria-pressed', String(btn.getAttribute('data-theme-choice') === mode)));
}

themeButtons.forEach(btn => {
  btn.addEventListener('click', () => applyTheme(btn.getAttribute('data-theme-choice')));
});

// Reflect the button state to match whatever the early inline <script>
// in index.html already applied (it runs before this file loads, to
// avoid a flash of the wrong theme).
applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');

// If the user is in "system" mode, follow live OS theme changes without
// needing a reload (CSS already does this via the media query; this
// keeps the meta theme-color and button state in sync too).
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (document.documentElement.getAttribute('data-theme') === 'system') applyTheme('system');
});

// --- Language ---
// Same per-device, localStorage-based approach as theme (see i18n.js).

const languageSelect = document.getElementById('language-select');
languageSelect.value = PVI18N.getLanguage();
languageSelect.addEventListener('change', () => {
  PVI18N.setLanguage(languageSelect.value);
});

// Re-render whatever dynamic content is currently visible so a language
// switch mid-session doesn't require a reload to take effect everywhere.
window.addEventListener('pv-lang-changed', () => {
  languageSelect.value = PVI18N.getLanguage();
  updateAuthModeText();
  if (encKey) {
    renderEntriesList();
    if (currentEntryId !== null) renderEntryDetail();
    renderExpenses();
    renderIncomes();
    renderNotes();
    renderAddresses();
    renderGoals();
    renderTodos();
    if (isAdmin) loadAdminData();
    if (chatLoaded) renderFullChatHistory();
  }
});

logoutBtn.addEventListener('click', async () => {
  clearTimeout(saveTimer);
  if (dirty) await saveVaultNow(); // flush any pending debounced save first
  await Api.logout();
  encKey = null;
  vault = { entries: [], budget: { expenses: [], incomes: [] }, notes: [], addresses: [], goals: [], todos: [] };
  editingPasswordIds.clear();
  currentEntryId = null;
  vaultListView.classList.remove('hidden');
  vaultDetailView.classList.add('hidden');
  stopChatPolling();
  chatMessages = [];
  lastMessageTime = null;
  chatLoaded = false;
  chatMessagesEl.innerHTML = '';
  isAdmin = false;
  adminSettingsSection.classList.add('hidden');
  vaultView.classList.add('hidden');
  authView.classList.remove('hidden');
  authForm.reset();
  passwordInput.type = 'password';
  masterPasswordToggle.setAttribute('aria-label', t('common.showPassword'));
  masterPasswordToggle.setAttribute('aria-pressed', 'false');
  mode = 'login';
  updateAuthModeText();
  inviteCodeField.classList.add('hidden');
  inviteCodeInput.required = false;
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
    cpError.textContent = t('cp.tooShort');
    return;
  }
  if (newPassword !== confirmPassword) {
    cpError.textContent = t('cp.mismatch');
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
      cpError.textContent = t('cp.wrongCurrent');
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
    announce(t('cp.changed'));
  } catch (err) {
    cpError.textContent = err.message || t('common.somethingWrong');
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
    announce(t('backup.success'));
  } catch (err) {
    announce(err.message || t('backup.failed'));
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
    alert(t('restore.badJson'));
    return;
  }
  if (parsed.app !== BACKUP_APP_ID || parsed.version !== BACKUP_VERSION || !parsed.salt || !parsed.iv || !parsed.blob) {
    alert(t('restore.badFormat'));
    return;
  }

  pendingRestore = parsed;
  restoreForm.reset();
  restoreError.textContent = '';
  restoreSubmitBtn.disabled = false;
  const info = t('restore.info', {
    username: parsed.username,
    exported: parsed.exportedAt ? t('restore.infoExported', { date: new Date(parsed.exportedAt).toLocaleString() }) : ''
  });
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
      restoreError.textContent = t('restore.wrongPassword');
      restoreSubmitBtn.disabled = false;
      return;
    }
    if (!restoredVault.entries) restoredVault.entries = [];
    ensurePasswordIds(restoredVault.entries);
    if (!restoredVault.budget) restoredVault.budget = { expenses: [], incomes: [] };
    if (!restoredVault.budget.expenses) restoredVault.budget.expenses = [];
    if (!restoredVault.budget.incomes) restoredVault.budget.incomes = [];
    if (!restoredVault.notes) restoredVault.notes = [];
    if (!restoredVault.addresses) restoredVault.addresses = [];
    if (!restoredVault.goals) restoredVault.goals = [];
    if (!restoredVault.todos) restoredVault.todos = [];

    const currentCount = t('restore.countSummary', { entries: vault.entries.length, expenses: vault.budget.expenses.length });
    const backupCount = t('restore.countSummary', { entries: restoredVault.entries.length, expenses: restoredVault.budget.expenses.length });
    const proceed = confirm(t('restore.confirm', { current: currentCount, backup: backupCount }));
    if (!proceed) {
      restoreSubmitBtn.disabled = false;
      return;
    }

    vault = restoredVault;
    editingPasswordIds.clear();
    currentEntryId = null;
    vaultListView.classList.remove('hidden');
    vaultDetailView.classList.add('hidden');
    dirty = true;
    await saveVaultNow();
    renderEntriesList();
    renderExpenses();
    renderIncomes(); // was missing before too - restore never refreshed the income rows
    renderNotes();
    renderAddresses();
    renderGoals();
    renderTodos();
    pendingRestore = null;
    restoreDialog.close();
    announce(t('restore.success'));
  } catch (err) {
    restoreError.textContent = err.message || t('common.somethingWrong');
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
      authError.textContent = t('auth.decryptFailed');
      encKey = null;
      return;
    }
  } else {
    vault = { entries: [] };
  }
  if (!vault.entries) vault.entries = [];
  ensurePasswordIds(vault.entries);
  if (!vault.budget) vault.budget = { expenses: [], incomes: [] };
  if (!vault.budget.expenses) vault.budget.expenses = [];
  if (!vault.budget.incomes) vault.budget.incomes = [];
  if (!vault.notes) vault.notes = [];
  if (!vault.addresses) vault.addresses = [];
  if (!vault.goals) vault.goals = [];
  if (!vault.todos) vault.todos = [];
  adminSettingsSection.classList.toggle('hidden', !isAdmin);
  authView.classList.add('hidden');
  vaultView.classList.remove('hidden');
  switchTab('vault');
  currentEntryId = null;
  vaultListView.classList.remove('hidden');
  vaultDetailView.classList.add('hidden');
  renderEntriesList();
  renderExpenses();
  renderIncomes();
  renderNotes();
  renderAddresses();
  renderGoals();
  renderTodos();
}

function newEntry() {
  return {
    id: crypto.randomUUID(),
    email: '',
    username: '',
    passwords: [{ id: crypto.randomUUID(), label: t('vault.passwordN', { n: 1 }), value: '' }],
    keyQuestions: []
  };
}

function renderEntriesList() {
  entriesListEl.innerHTML = '';
  const query = vaultSearchQuery.trim().toLowerCase();
  const filtered = query
    ? vault.entries.filter(e =>
        (e.email || '').toLowerCase().includes(query) ||
        (e.username || '').toLowerCase().includes(query))
    : vault.entries;

  if (vault.entries.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'expenses-empty';
    empty.textContent = t('vault.emptyNoEntries');
    entriesListEl.appendChild(empty);
  } else if (filtered.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'expenses-empty';
    empty.textContent = t('vault.emptySearch');
    entriesListEl.appendChild(empty);
  } else {
    filtered.forEach(entry => entriesListEl.appendChild(renderEntryListRow(entry)));
  }
}

function renderEntryListRow(entry) {
  const row = document.createElement('button');
  row.type = 'button';
  row.className = 'entry-list-row';
  row.setAttribute('aria-label', t('vault.openEntryAria', {
    email: entry.email || t('vault.entryNoEmailAria'),
    userPart: entry.username ? t('vault.openEntryUserPart', { username: entry.username }) : ''
  }));
  row.addEventListener('click', () => openEntryDetail(entry.id));

  const icon = document.createElement('span');
  icon.className = 'entry-list-icon';
  icon.textContent = '🔒';
  icon.setAttribute('aria-hidden', 'true');

  const info = document.createElement('span');
  info.className = 'entry-list-info';
  const emailEl = document.createElement('span');
  emailEl.className = 'entry-list-email';
  emailEl.textContent = entry.email || t('vault.noEmail');
  info.appendChild(emailEl);
  if (entry.username) {
    const userEl = document.createElement('span');
    userEl.className = 'entry-list-username';
    userEl.textContent = entry.username;
    info.appendChild(userEl);
  }

  const chevron = document.createElement('span');
  chevron.className = 'entry-list-chevron';
  chevron.textContent = '›';
  chevron.setAttribute('aria-hidden', 'true');

  row.appendChild(icon);
  row.appendChild(info);
  row.appendChild(chevron);
  return row;
}

function openEntryDetail(entryId) {
  currentEntryId = entryId;
  vaultListView.classList.add('hidden');
  vaultDetailView.classList.remove('hidden');
  renderEntryDetail();
}

function closeEntryDetail() {
  currentEntryId = null;
  vaultDetailView.classList.add('hidden');
  vaultListView.classList.remove('hidden');
  renderEntriesList();
}

function renderEntryDetail() {
  entriesEl.innerHTML = '';
  const idx = vault.entries.findIndex(e => e.id === currentEntryId);
  if (idx === -1) { closeEntryDetail(); return; }
  entriesEl.appendChild(renderEntry(vault.entries[idx], idx));
}

function renderEntry(entry, idx) {
  const card = document.createElement('div');
  card.className = 'entry-card';

  // Header: editable email address
  const header = document.createElement('div');
  header.className = 'entry-header';
  const emailInput = document.createElement('input');
  emailInput.type = 'text';
  emailInput.placeholder = t('vault.emailPlaceholder');
  emailInput.setAttribute('aria-label', t('vault.emailHeaderAria'));
  emailInput.autocomplete = 'off';
  emailInput.value = entry.email;
  emailInput.className = 'email-input';
  emailInput.addEventListener('input', () => { entry.email = emailInput.value; markDirty(); });
  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = t('vault.removeSectionTitle');
  removeBtn.setAttribute('aria-label', t('vault.removeSectionAria', { email: entry.email || t('vault.noEmail') }));
  removeBtn.addEventListener('click', () => {
    if (confirm(t('vault.removeSectionConfirm', { email: entry.email || t('vault.noEmail') }))) {
      vault.entries.splice(idx, 1);
      markDirty();
      closeEntryDetail();
    }
  });
  header.appendChild(emailInput);
  header.appendChild(removeBtn);
  card.appendChild(header);

  const body = document.createElement('div');
  body.className = 'entry-body';

  // Username
  const userLabel = document.createElement('label');
  userLabel.textContent = t('common.username');
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
  pwTitle.textContent = t('vault.passwordsTitle');
  pwSection.appendChild(pwTitle);

  const pwList = document.createElement('div');
  entry.passwords.forEach((pw, pwIdx) => {
    pwList.appendChild(renderPasswordRow(entry, pw, pwIdx));
  });
  pwSection.appendChild(pwList);

  const addPwBtn = document.createElement('button');
  addPwBtn.className = 'link-btn';
  addPwBtn.textContent = t('vault.addPassword');
  addPwBtn.addEventListener('click', () => {
    if (entry.passwords.length >= 5) return;
    const newPw = { id: crypto.randomUUID(), label: t('vault.passwordN', { n: entry.passwords.length + 1 }), value: '' };
    entry.passwords.push(newPw);
    editingPasswordIds.add(newPw.id);
    markDirty();
    renderEntryDetail();
  });
  if (entry.passwords.length >= 5) addPwBtn.disabled = true;
  pwSection.appendChild(addPwBtn);
  body.appendChild(pwSection);

  // Key Questions
  const kqSection = document.createElement('div');
  kqSection.className = 'sub-section';
  const kqTitle = document.createElement('div');
  kqTitle.className = 'sub-title';
  kqTitle.textContent = t('vault.keyQuestionsTitle');
  kqSection.appendChild(kqTitle);

  entry.keyQuestions.forEach((kq, kqIdx) => {
    kqSection.appendChild(renderKeyQuestionRow(entry, kq, kqIdx));
  });

  const addKqBtn = document.createElement('button');
  addKqBtn.className = 'link-btn';
  addKqBtn.textContent = t('vault.addKeyQuestion');
  addKqBtn.addEventListener('click', () => {
    entry.keyQuestions.push({ question: '', answer: '' });
    markDirty();
    renderEntryDetail();
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
  const isEditing = editingPasswordIds.has(pw.id);

  const labelInput = document.createElement('input');
  labelInput.type = 'text';
  labelInput.className = 'pw-label';
  labelInput.setAttribute('aria-label', t('vault.pwLabelAria', { n: pwIdx + 1 }));
  labelInput.autocomplete = 'off';
  labelInput.readOnly = !isEditing;
  labelInput.value = pw.label || t('vault.passwordN', { n: pwIdx + 1 });
  labelInput.addEventListener('input', () => { pw.label = labelInput.value; markDirty(); });

  const valueInput = document.createElement('input');
  valueInput.type = 'password';
  valueInput.className = 'pw-value';
  valueInput.setAttribute('aria-label', t('vault.pwValueAria', { label: pw.label || t('vault.passwordN', { n: pwIdx + 1 }) }));
  valueInput.autocomplete = 'off';
  valueInput.readOnly = !isEditing;
  valueInput.value = pw.value;
  valueInput.placeholder = t('common.password');
  valueInput.addEventListener('input', () => { pw.value = valueInput.value; markDirty(); });

  const generateBtn = document.createElement('button');
  generateBtn.className = 'icon-btn';
  generateBtn.textContent = '🎲';
  generateBtn.title = t('vault.generateTitle');
  generateBtn.setAttribute('aria-label', t('vault.generateAria', { label: pw.label || t('vault.passwordN', { n: pwIdx + 1 }) }));
  generateBtn.addEventListener('click', () => {
    if (pw.value) {
      if (!confirm(t('vault.regenConfirm'))) return;
    }
    const generated = generatePasswordFn(generatorOptions.length, generatorOptions);
    if (!generated) {
      announce(t('generator.selectTypeFirst'));
      return;
    }
    pw.value = generated;
    valueInput.value = generated;
    valueInput.type = 'text'; // reveal it briefly so there's a chance to see what was generated
    toggleBtn.setAttribute('aria-label', t('common.hidePassword'));
    toggleBtn.setAttribute('aria-pressed', 'true');
    markDirty();
    announce(t('vault.generatedAnnounce', { label: pw.label || t('vault.passwordN', { n: pwIdx + 1 }) }));
  });

  const toggleBtn = document.createElement('button');
  toggleBtn.className = 'icon-btn';
  toggleBtn.textContent = '👁';
  toggleBtn.title = t('common.showHide');
  toggleBtn.setAttribute('aria-label', t('common.showPassword'));
  toggleBtn.setAttribute('aria-pressed', 'false');
  toggleBtn.addEventListener('click', () => {
    const nowVisible = valueInput.type === 'password';
    valueInput.type = nowVisible ? 'text' : 'password';
    toggleBtn.setAttribute('aria-label', nowVisible ? t('common.hidePassword') : t('common.showPassword'));
    toggleBtn.setAttribute('aria-pressed', String(nowVisible));
  });

  const copyBtn = document.createElement('button');
  copyBtn.className = 'icon-btn';
  copyBtn.textContent = '📋';
  copyBtn.title = t('generator.copyTitle');
  copyBtn.setAttribute('aria-label', t('vault.copyPasswordAria'));
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
    announce(t('vault.copiedAnnounce'));
    // Clear the clipboard after a delay, but only if it still holds
    // what we put there (avoid clobbering something the user copied since).
    clearClipboardAfter(copiedValue, 20000);
  });

  const editToggleBtn = document.createElement('button');
  editToggleBtn.className = 'icon-btn';
  editToggleBtn.textContent = isEditing ? '✓' : '✏️';
  editToggleBtn.title = isEditing ? t('common.doneEditing') : t('common.edit');
  editToggleBtn.setAttribute('aria-label', t('vault.editToggleAria', { action: isEditing ? t('common.doneEditing') : t('common.edit'), label: pw.label || t('vault.passwordN', { n: pwIdx + 1 }) }));
  editToggleBtn.setAttribute('aria-pressed', String(isEditing));
  editToggleBtn.addEventListener('click', () => {
    if (isEditing) editingPasswordIds.delete(pw.id); else editingPasswordIds.add(pw.id);
    renderEntryDetail();
  });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = t('vault.removePasswordTitle');
  removeBtn.setAttribute('aria-label', t('vault.removePasswordAria', { label: pw.label || t('vault.passwordN', { n: pwIdx + 1 }) }));
  removeBtn.addEventListener('click', () => {
    const label = pw.label || t('vault.passwordN', { n: pwIdx + 1 });
    if (!confirm(t('vault.removePasswordConfirm', { label }))) return;
    editingPasswordIds.delete(pw.id);
    entry.passwords.splice(pwIdx, 1);
    markDirty();
    renderEntryDetail();
  });

  row.appendChild(labelInput);
  row.appendChild(valueInput);
  if (isEditing) row.appendChild(generateBtn);
  row.appendChild(toggleBtn);
  row.appendChild(copyBtn);
  row.appendChild(editToggleBtn);
  if (isEditing) row.appendChild(removeBtn);
  return row;
}

function renderKeyQuestionRow(entry, kq, kqIdx) {
  const row = document.createElement('div');
  row.className = 'kq-row';

  const qInput = document.createElement('input');
  qInput.type = 'text';
  qInput.placeholder = t('vault.kqPlaceholder');
  qInput.setAttribute('aria-label', t('vault.kqAria', { n: kqIdx + 1 }));
  qInput.autocomplete = 'off';
  qInput.value = kq.question;
  qInput.addEventListener('input', () => { kq.question = qInput.value; markDirty(); });

  const aInput = document.createElement('input');
  aInput.type = 'text';
  aInput.placeholder = t('vault.kqAnswerPlaceholder');
  aInput.setAttribute('aria-label', t('vault.kqAnswerAria', { n: kqIdx + 1 }));
  aInput.autocomplete = 'off';
  aInput.value = kq.answer;
  aInput.addEventListener('input', () => { kq.answer = aInput.value; markDirty(); });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = t('vault.removeKqTitle');
  removeBtn.setAttribute('aria-label', t('vault.removeKqAria', { n: kqIdx + 1 }));
  removeBtn.addEventListener('click', () => {
    if (!confirm(t('vault.removeKqConfirm'))) return;
    entry.keyQuestions.splice(kqIdx, 1);
    markDirty();
    renderEntryDetail();
  });

  row.appendChild(qInput);
  row.appendChild(aInput);
  row.appendChild(removeBtn);
  return row;
}

addEntryBtn.addEventListener('click', () => {
  const entry = newEntry();
  editingPasswordIds.add(entry.passwords[0].id);
  vault.entries.unshift(entry);
  markDirty();
  openEntryDetail(entry.id);
});

vaultSearchInput.addEventListener('input', () => {
  vaultSearchQuery = vaultSearchInput.value;
  renderEntriesList();
});

vaultBackBtn.addEventListener('click', closeEntryDetail);

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

function newIncome() {
  return {
    id: crypto.randomUUID(),
    date: new Date().toISOString().slice(0, 10),
    source: '',
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
    empty.textContent = t('budget.emptyExpenses');
    expensesEl.appendChild(empty);
  } else {
    expenses.forEach((expense, idx) => {
      expensesEl.appendChild(renderExpenseRow(expense, idx));
    });
  }
  renderBudgetSummary();
}

function renderIncomes() {
  incomesEl.innerHTML = '';
  const incomes = vault.budget.incomes;
  if (incomes.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'expenses-empty';
    empty.textContent = t('budget.emptyIncome');
    incomesEl.appendChild(empty);
  } else {
    incomes.forEach((income, idx) => {
      incomesEl.appendChild(renderIncomeRow(income, idx));
    });
  }
  renderBudgetSummary();
}

function renderBudgetSummary() {
  const expenses = vault.budget.expenses;
  const incomes = vault.budget.incomes;
  const expenseTotal = expenses.reduce((sum, e) => sum + (Number(e.amount) || 0), 0);
  const incomeTotal = incomes.reduce((sum, i) => sum + (Number(i.amount) || 0), 0);
  const net = incomeTotal - expenseTotal;

  budgetTotalEl.textContent = expenseTotal.toFixed(2);
  budgetIncomeTotalEl.textContent = incomeTotal.toFixed(2);
  budgetNetEl.textContent = (net >= 0 ? '' : '-') + Math.abs(net).toFixed(2);
  budgetNetEl.classList.toggle('positive', net > 0);
  budgetNetEl.classList.toggle('negative', net < 0);

  renderExpenseChart(expenses);
}

// A simple single-hue bar chart (magnitude comparison, not identity — every
// bar shares one color and the category name is its own direct label, per
// dataviz guidance for comparing a nominal set of categories).
function renderExpenseChart(expenses) {
  const byCategory = new Map();
  expenses.forEach(e => {
    const key = (e.category || '').trim() || t('budget.uncategorized');
    byCategory.set(key, (byCategory.get(key) || 0) + (Number(e.amount) || 0));
  });

  budgetChartEl.innerHTML = '';
  if (byCategory.size === 0) {
    const empty = document.createElement('div');
    empty.className = 'chart-empty';
    empty.textContent = t('budget.emptyChart');
    budgetChartEl.appendChild(empty);
    return;
  }
  const sorted = [...byCategory.entries()].sort((a, b) => b[1] - a[1]);
  const max = sorted[0][1] || 1;
  sorted.forEach(([category, amount]) => {
    const row = document.createElement('div');
    row.className = 'chart-row';

    const header = document.createElement('div');
    header.className = 'chart-row-header';
    const labelEl = document.createElement('span');
    labelEl.className = 'chart-row-label';
    labelEl.textContent = category;
    const valueEl = document.createElement('span');
    valueEl.className = 'chart-row-value';
    valueEl.textContent = amount.toFixed(2);
    header.appendChild(labelEl);
    header.appendChild(valueEl);

    const track = document.createElement('div');
    track.className = 'chart-bar-track';
    const fill = document.createElement('div');
    fill.className = 'chart-bar-fill';
    fill.style.width = Math.max((amount / max) * 100, 2) + '%';
    track.appendChild(fill);

    row.appendChild(header);
    row.appendChild(track);
    budgetChartEl.appendChild(row);
  });
}

function renderExpenseRow(expense, idx) {
  const row = document.createElement('div');
  row.className = 'expense-row';

  const dateInput = document.createElement('input');
  dateInput.type = 'date';
  dateInput.className = 'expense-date';
  dateInput.setAttribute('aria-label', t('budget.expenseDateAria'));
  dateInput.value = expense.date || '';
  dateInput.addEventListener('input', () => { expense.date = dateInput.value; markDirty(); });

  const categoryInput = document.createElement('input');
  categoryInput.type = 'text';
  categoryInput.className = 'expense-category';
  categoryInput.placeholder = t('budget.categoryPlaceholder');
  categoryInput.setAttribute('aria-label', t('budget.expenseCategoryAria'));
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
  descInput.placeholder = t('common.descriptionPlaceholder');
  descInput.setAttribute('aria-label', t('budget.expenseDescAria'));
  descInput.autocomplete = 'off';
  descInput.value = expense.description || '';
  descInput.addEventListener('input', () => { expense.description = descInput.value; markDirty(); });

  const amountInput = document.createElement('input');
  amountInput.type = 'number';
  amountInput.className = 'expense-amount';
  amountInput.placeholder = '0.00';
  amountInput.step = '0.01';
  amountInput.min = '0';
  amountInput.setAttribute('aria-label', t('budget.expenseAmountAria'));
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
  removeBtn.title = t('budget.removeExpenseTitle');
  removeBtn.setAttribute('aria-label', t('budget.removeExpenseAria', { detail: expense.description ? t('budget.removeExpenseAriaDetail', { description: expense.description }) : ' ' + (idx + 1) }));
  removeBtn.addEventListener('click', () => {
    if (!confirm(t('budget.removeExpenseConfirm'))) return;
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

function renderIncomeRow(income, idx) {
  const row = document.createElement('div');
  row.className = 'expense-row';

  const dateInput = document.createElement('input');
  dateInput.type = 'date';
  dateInput.className = 'expense-date';
  dateInput.setAttribute('aria-label', t('budget.incomeDateAria'));
  dateInput.value = income.date || '';
  dateInput.addEventListener('input', () => { income.date = dateInput.value; markDirty(); });

  const sourceInput = document.createElement('input');
  sourceInput.type = 'text';
  sourceInput.className = 'expense-category';
  sourceInput.placeholder = t('budget.sourcePlaceholder');
  sourceInput.setAttribute('aria-label', t('budget.incomeSourceAria'));
  sourceInput.autocomplete = 'off';
  sourceInput.value = income.source || '';
  sourceInput.addEventListener('input', () => { income.source = sourceInput.value; markDirty(); });

  const descInput = document.createElement('input');
  descInput.type = 'text';
  descInput.className = 'expense-description';
  descInput.placeholder = t('common.descriptionPlaceholder');
  descInput.setAttribute('aria-label', t('budget.incomeDescAria'));
  descInput.autocomplete = 'off';
  descInput.value = income.description || '';
  descInput.addEventListener('input', () => { income.description = descInput.value; markDirty(); });

  const amountInput = document.createElement('input');
  amountInput.type = 'number';
  amountInput.className = 'expense-amount';
  amountInput.placeholder = '0.00';
  amountInput.step = '0.01';
  amountInput.min = '0';
  amountInput.setAttribute('aria-label', t('budget.incomeAmountAria'));
  amountInput.autocomplete = 'off';
  amountInput.value = income.amount === 0 ? '' : income.amount;
  amountInput.addEventListener('input', () => {
    income.amount = parseFloat(amountInput.value) || 0;
    markDirty();
    renderBudgetSummary();
  });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = t('budget.removeIncomeTitle');
  removeBtn.setAttribute('aria-label', t('budget.removeIncomeAria', { detail: income.description ? t('budget.removeExpenseAriaDetail', { description: income.description }) : ' ' + (idx + 1) }));
  removeBtn.addEventListener('click', () => {
    if (!confirm(t('budget.removeIncomeConfirm'))) return;
    vault.budget.incomes.splice(idx, 1);
    markDirty();
    renderIncomes();
  });

  row.appendChild(dateInput);
  row.appendChild(sourceInput);
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

addIncomeBtn.addEventListener('click', () => {
  vault.budget.incomes.unshift(newIncome());
  markDirty();
  renderIncomes();
});

// --- To-Do ---

function newTodo(text) {
  return {
    id: crypto.randomUUID(),
    text: text || '',
    done: false,
    dueDate: '',
    createdAt: new Date().toISOString()
  };
}

function sortedTodos() {
  // Incomplete first, each group newest-first.
  return [...vault.todos].sort((a, b) => {
    if (a.done !== b.done) return a.done ? 1 : -1;
    return b.createdAt.localeCompare(a.createdAt);
  });
}

function renderTodos() {
  todoListEl.innerHTML = '';
  const todos = sortedTodos();
  if (todos.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'expenses-empty';
    empty.textContent = t('todo.empty');
    todoListEl.appendChild(empty);
    return;
  }
  todos.forEach(todo => todoListEl.appendChild(renderTodoRow(todo)));
}

function renderTodoRow(todo) {
  const row = document.createElement('div');
  row.className = 'todo-row' + (todo.done ? ' done' : '');

  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.className = 'todo-checkbox';
  checkbox.checked = todo.done;
  checkbox.setAttribute('aria-label', t(todo.done ? 'todo.markIncompleteAria' : 'todo.markCompleteAria', { text: todo.text || t('todo.taskFallback') }));
  checkbox.addEventListener('change', () => {
    todo.done = checkbox.checked;
    markDirty();
    renderTodos();
  });

  const textInput = document.createElement('input');
  textInput.type = 'text';
  textInput.className = 'todo-text';
  textInput.placeholder = t('todo.taskPlaceholder');
  textInput.setAttribute('aria-label', t('todo.taskTextAria'));
  textInput.autocomplete = 'off';
  textInput.value = todo.text || '';
  textInput.addEventListener('input', () => { todo.text = textInput.value; markDirty(); });

  const dueInput = document.createElement('input');
  dueInput.type = 'date';
  dueInput.className = 'todo-due';
  dueInput.setAttribute('aria-label', t('common.dueDateAria'));
  dueInput.value = todo.dueDate || '';
  dueInput.addEventListener('input', () => { todo.dueDate = dueInput.value; markDirty(); });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = t('todo.deleteTitle');
  removeBtn.setAttribute('aria-label', t('todo.deleteAria', { detail: todo.text ? t('todo.deleteAriaDetail', { text: todo.text }) : '' }));
  removeBtn.addEventListener('click', () => {
    const idx = vault.todos.findIndex(x => x.id === todo.id);
    if (idx !== -1) vault.todos.splice(idx, 1);
    markDirty();
    renderTodos();
    announce(t('todo.deletedAnnounce'));
  });

  row.appendChild(checkbox);
  row.appendChild(textInput);
  row.appendChild(dueInput);
  row.appendChild(removeBtn);
  return row;
}

newTodoInput.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  const text = newTodoInput.value.trim();
  if (!text) return;
  vault.todos.unshift(newTodo(text));
  newTodoInput.value = '';
  markDirty();
  renderTodos();
  announce(t('todo.addedAnnounce'));
});

// --- Goals ---

function newGoal() {
  return {
    id: crypto.randomUUID(),
    title: '',
    description: '',
    targetDate: '',
    status: 'not-started', // used when no numeric target is set
    target: null,          // numeric target, e.g. a dollar amount or count
    current: 0
  };
}

function renderGoals() {
  goalsListEl.innerHTML = '';
  const goals = vault.goals;
  if (goals.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'expenses-empty';
    empty.textContent = t('goals.empty');
    goalsListEl.appendChild(empty);
    return;
  }
  goals.forEach((goal, idx) => goalsListEl.appendChild(renderGoalRow(goal, idx)));
}

function renderGoalRow(goal, idx) {
  const row = document.createElement('div');
  row.className = 'goal-row';

  const topLine = document.createElement('div');
  topLine.className = 'goal-row-top';

  const titleInput = document.createElement('input');
  titleInput.type = 'text';
  titleInput.className = 'goal-title';
  titleInput.placeholder = t('goals.titlePlaceholder');
  titleInput.setAttribute('aria-label', t('goals.titleAria'));
  titleInput.autocomplete = 'off';
  titleInput.value = goal.title || '';
  titleInput.addEventListener('input', () => { goal.title = titleInput.value; markDirty(); });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = t('goals.deleteTitle');
  removeBtn.setAttribute('aria-label', t('goals.deleteAria', { detail: goal.title ? t('goals.deleteAriaDetail', { title: goal.title }) : t('goals.deleteAriaIndex', { n: idx + 1 }) }));
  removeBtn.addEventListener('click', () => {
    if (!confirm(t('goals.removeConfirm'))) return;
    vault.goals.splice(idx, 1);
    markDirty();
    renderGoals();
  });

  topLine.appendChild(titleInput);
  topLine.appendChild(removeBtn);

  const descInput = document.createElement('input');
  descInput.type = 'text';
  descInput.className = 'goal-description';
  descInput.placeholder = t('common.descriptionOptionalPlaceholder');
  descInput.setAttribute('aria-label', t('goals.descAria'));
  descInput.autocomplete = 'off';
  descInput.value = goal.description || '';
  descInput.addEventListener('input', () => { goal.description = descInput.value; markDirty(); });

  const metaLine = document.createElement('div');
  metaLine.className = 'goal-row-meta';

  const dateInput = document.createElement('input');
  dateInput.type = 'date';
  dateInput.className = 'goal-target-date';
  dateInput.setAttribute('aria-label', t('goals.targetDateAria'));
  dateInput.value = goal.targetDate || '';
  dateInput.addEventListener('input', () => { goal.targetDate = dateInput.value; markDirty(); });

  const hasTarget = goal.target !== null && goal.target !== undefined && goal.target !== '';

  const targetToggle = document.createElement('label');
  targetToggle.className = 'goal-target-toggle';
  const targetCheckbox = document.createElement('input');
  targetCheckbox.type = 'checkbox';
  targetCheckbox.checked = hasTarget;
  targetCheckbox.setAttribute('aria-label', t('goals.trackTargetAria'));
  targetToggle.appendChild(targetCheckbox);
  targetToggle.appendChild(document.createTextNode(t('goals.numericTargetLabel')));

  metaLine.appendChild(dateInput);
  metaLine.appendChild(targetToggle);

  row.appendChild(topLine);
  row.appendChild(descInput);
  row.appendChild(metaLine);

  const progressWrap = document.createElement('div');
  progressWrap.className = 'goal-progress-wrap';

  function renderProgressSection() {
    progressWrap.innerHTML = '';
    if (targetCheckbox.checked) {
      const nums = document.createElement('div');
      nums.className = 'goal-progress-nums';

      const currentInput = document.createElement('input');
      currentInput.type = 'number';
      currentInput.className = 'goal-current';
      currentInput.setAttribute('aria-label', t('goals.currentProgressAria'));
      currentInput.value = goal.current || 0;
      currentInput.addEventListener('input', () => {
        goal.current = parseFloat(currentInput.value) || 0;
        markDirty();
        renderProgressBar();
      });

      const sep = document.createElement('span');
      sep.textContent = t('goals.ofSeparator');

      const targetInput = document.createElement('input');
      targetInput.type = 'number';
      targetInput.className = 'goal-target';
      targetInput.setAttribute('aria-label', t('goals.targetAmountAria'));
      targetInput.value = goal.target || '';
      targetInput.addEventListener('input', () => {
        goal.target = parseFloat(targetInput.value) || 0;
        markDirty();
        renderProgressBar();
      });

      nums.appendChild(currentInput);
      nums.appendChild(sep);
      nums.appendChild(targetInput);
      progressWrap.appendChild(nums);

      const track = document.createElement('div');
      track.className = 'chart-bar-track goal-progress-track';
      const fill = document.createElement('div');
      fill.className = 'chart-bar-fill';
      track.appendChild(fill);
      progressWrap.appendChild(track);

      function renderProgressBar() {
        const pct = goal.target > 0 ? Math.min((goal.current / goal.target) * 100, 100) : 0;
        fill.style.width = Math.max(pct, goal.current > 0 ? 2 : 0) + '%';
      }
      renderProgressBar();
    } else {
      const statusSelect = document.createElement('select');
      statusSelect.className = 'goal-status';
      statusSelect.setAttribute('aria-label', t('goals.statusAria'));
      [['not-started', 'goals.statusNotStarted'], ['in-progress', 'goals.statusInProgress'], ['done', 'goals.statusDone']].forEach(([value, key]) => {
        const opt = document.createElement('option');
        opt.value = value;
        opt.textContent = t(key);
        if (goal.status === value) opt.selected = true;
        statusSelect.appendChild(opt);
      });
      statusSelect.addEventListener('change', () => { goal.status = statusSelect.value; markDirty(); });
      progressWrap.appendChild(statusSelect);
    }
  }

  targetCheckbox.addEventListener('change', () => {
    if (targetCheckbox.checked) {
      goal.target = goal.target || 0;
    } else {
      goal.target = null;
    }
    markDirty();
    renderProgressSection();
  });

  renderProgressSection();
  row.appendChild(progressWrap);

  return row;
}

addGoalBtn.addEventListener('click', () => {
  vault.goals.unshift(newGoal());
  markDirty();
  renderGoals();
});

// --- Addresses ---

const US_STATES = [
  'Alabama', 'Alaska', 'Arizona', 'Arkansas', 'California', 'Colorado', 'Connecticut', 'Delaware',
  'District of Columbia', 'Florida', 'Georgia', 'Hawaii', 'Idaho', 'Illinois', 'Indiana', 'Iowa',
  'Kansas', 'Kentucky', 'Louisiana', 'Maine', 'Maryland', 'Massachusetts', 'Michigan', 'Minnesota',
  'Mississippi', 'Missouri', 'Montana', 'Nebraska', 'Nevada', 'New Hampshire', 'New Jersey', 'New Mexico',
  'New York', 'North Carolina', 'North Dakota', 'Ohio', 'Oklahoma', 'Oregon', 'Pennsylvania', 'Rhode Island',
  'South Carolina', 'South Dakota', 'Tennessee', 'Texas', 'Utah', 'Vermont', 'Virginia', 'Washington',
  'West Virginia', 'Wisconsin', 'Wyoming'
];

let statesDatalistEl = null;
function ensureStatesDatalist() {
  if (statesDatalistEl) return statesDatalistEl;
  statesDatalistEl = document.createElement('datalist');
  statesDatalistEl.id = 'us-states-list';
  US_STATES.forEach(state => {
    const opt = document.createElement('option');
    opt.value = state;
    statesDatalistEl.appendChild(opt);
  });
  document.body.appendChild(statesDatalistEl);
  return statesDatalistEl;
}

function newAddress() {
  return {
    id: crypto.randomUUID(),
    place: '',
    address: '',
    state: '',
    phone: '',
    dateUsed: '',
    status: 'active',   // active | moved-out
    category: ''
  };
}

function renderAddresses() {
  ensureStatesDatalist();
  addressesListEl.innerHTML = '';
  const addresses = vault.addresses;
  if (addresses.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'expenses-empty';
    empty.textContent = t('addresses.empty');
    addressesListEl.appendChild(empty);
    return;
  }
  addresses.forEach((addr, idx) => addressesListEl.appendChild(renderAddressRow(addr, idx)));
}

function renderAddressRow(addr, idx) {
  const row = document.createElement('div');
  row.className = 'address-row';

  const topLine = document.createElement('div');
  topLine.className = 'address-row-top';

  const placeInput = document.createElement('input');
  placeInput.type = 'text';
  placeInput.className = 'address-place';
  placeInput.placeholder = t('addresses.placePlaceholder');
  placeInput.setAttribute('aria-label', t('addresses.placeAria'));
  placeInput.autocomplete = 'off';
  placeInput.value = addr.place || '';
  placeInput.addEventListener('input', () => { addr.place = placeInput.value; markDirty(); });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = t('addresses.deleteTitle');
  removeBtn.setAttribute('aria-label', t('addresses.deleteAria', { detail: addr.place ? t('addresses.deleteAriaDetail', { place: addr.place }) : t('addresses.deleteAriaIndex', { n: idx + 1 }) }));
  removeBtn.addEventListener('click', () => {
    if (!confirm(t('addresses.removeConfirm'))) return;
    vault.addresses.splice(idx, 1);
    markDirty();
    renderAddresses();
  });

  topLine.appendChild(placeInput);
  topLine.appendChild(removeBtn);

  const addressInput = document.createElement('input');
  addressInput.type = 'text';
  addressInput.className = 'address-street';
  addressInput.placeholder = t('addresses.addressPlaceholder');
  addressInput.setAttribute('aria-label', t('addresses.addressAria'));
  addressInput.autocomplete = 'off';
  addressInput.value = addr.address || '';
  addressInput.addEventListener('input', () => { addr.address = addressInput.value; markDirty(); });

  const metaLine = document.createElement('div');
  metaLine.className = 'address-row-meta';

  const stateInput = document.createElement('input');
  stateInput.type = 'text';
  stateInput.className = 'address-state';
  stateInput.placeholder = t('addresses.statePlaceholder');
  stateInput.setAttribute('aria-label', t('addresses.stateAria'));
  stateInput.setAttribute('list', 'us-states-list');
  stateInput.autocomplete = 'off';
  stateInput.value = addr.state || '';
  stateInput.addEventListener('input', () => { addr.state = stateInput.value; markDirty(); });

  const categoryInput = document.createElement('input');
  categoryInput.type = 'text';
  categoryInput.className = 'address-category';
  categoryInput.placeholder = t('addresses.categoryPlaceholder');
  categoryInput.setAttribute('aria-label', t('addresses.categoryAria'));
  categoryInput.autocomplete = 'off';
  categoryInput.value = addr.category || '';
  categoryInput.addEventListener('input', () => { addr.category = categoryInput.value; markDirty(); });

  const dateInput = document.createElement('input');
  dateInput.type = 'date';
  dateInput.className = 'address-date-used';
  dateInput.setAttribute('aria-label', t('addresses.dateUsedAria'));
  dateInput.value = addr.dateUsed || '';
  dateInput.addEventListener('input', () => { addr.dateUsed = dateInput.value; markDirty(); });

  metaLine.appendChild(stateInput);
  metaLine.appendChild(categoryInput);
  metaLine.appendChild(dateInput);

  const phoneLine = document.createElement('div');
  phoneLine.className = 'address-row-phone';

  const phoneInput = document.createElement('input');
  phoneInput.type = 'tel';
  phoneInput.className = 'address-phone';
  phoneInput.placeholder = t('addresses.phonePlaceholder');
  phoneInput.setAttribute('aria-label', t('addresses.phoneAria'));
  phoneInput.autocomplete = 'off';
  phoneInput.value = addr.phone || '';
  phoneInput.addEventListener('input', () => {
    addr.phone = phoneInput.value;
    markDirty();
    updatePhoneLink();
  });

  const phoneLink = document.createElement('a');
  phoneLink.className = 'address-phone-link';
  phoneLink.textContent = '📞';
  phoneLink.title = t('addresses.callTitle');

  const copyPhoneBtn = document.createElement('button');
  copyPhoneBtn.className = 'icon-btn';
  copyPhoneBtn.textContent = '⧉';
  copyPhoneBtn.title = t('addresses.copyPhoneTitle');
  copyPhoneBtn.setAttribute('aria-label', t('addresses.copyPhoneAria'));
  copyPhoneBtn.addEventListener('click', async () => {
    if (!addr.phone) return;
    await navigator.clipboard.writeText(addr.phone);
    announce(t('addresses.copiedAnnounce'));
  });

  function updatePhoneLink() {
    const has = !!addr.phone;
    phoneLink.classList.toggle('hidden', !has);
    copyPhoneBtn.classList.toggle('hidden', !has);
    if (has) phoneLink.href = 'tel:' + addr.phone.replace(/[^0-9+]/g, '');
  }
  updatePhoneLink();

  phoneLine.appendChild(phoneInput);
  phoneLine.appendChild(phoneLink);
  phoneLine.appendChild(copyPhoneBtn);

  const statusSelect = document.createElement('select');
  statusSelect.className = 'address-status';
  statusSelect.setAttribute('aria-label', t('addresses.statusAria'));
  [['active', 'addresses.statusActive'], ['moved-out', 'addresses.statusMovedOut']].forEach(([value, key]) => {
    const opt = document.createElement('option');
    opt.value = value;
    opt.textContent = t(key);
    if ((addr.status || 'active') === value) opt.selected = true;
    statusSelect.appendChild(opt);
  });
  statusSelect.addEventListener('change', () => { addr.status = statusSelect.value; markDirty(); });

  row.appendChild(topLine);
  row.appendChild(addressInput);
  row.appendChild(metaLine);
  row.appendChild(phoneLine);
  row.appendChild(statusSelect);

  return row;
}

addAddressBtn.addEventListener('click', () => {
  vault.addresses.unshift(newAddress());
  markDirty();
  renderAddresses();
});

// --- Notes ---

const NOTE_COLORS = ['#fff6b7', '#c9f2c7', '#c7e3f2', '#f2c7e6', '#e3d7f7', '#e8e8e8'];

function newNote() {
  return {
    id: crypto.randomUUID(),
    title: '',
    body: '',
    color: NOTE_COLORS[0],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

function sortedNotes() {
  return [...vault.notes].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function renderNotes() {
  notesListEl.innerHTML = '';
  const notes = sortedNotes();
  if (notes.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'expenses-empty';
    empty.textContent = t('notes.empty');
    notesListEl.appendChild(empty);
    return;
  }
  notes.forEach(note => notesListEl.appendChild(renderNoteCard(note)));
}

function renderNoteCard(note) {
  const card = document.createElement('div');
  card.className = 'note-card';
  card.style.background = note.color || NOTE_COLORS[0];

  const topRow = document.createElement('div');
  topRow.className = 'note-card-top';

  const titleInput = document.createElement('input');
  titleInput.type = 'text';
  titleInput.className = 'note-title';
  titleInput.placeholder = t('notes.titlePlaceholder');
  titleInput.setAttribute('aria-label', t('notes.titleAria'));
  titleInput.autocomplete = 'off';
  titleInput.value = note.title || '';
  titleInput.addEventListener('input', () => {
    note.title = titleInput.value;
    note.updatedAt = new Date().toISOString();
    markDirty();
  });

  const removeBtn = document.createElement('button');
  removeBtn.className = 'icon-btn danger';
  removeBtn.textContent = '✕';
  removeBtn.title = t('notes.deleteTitle');
  removeBtn.setAttribute('aria-label', t('notes.deleteAria', { detail: note.title ? t('notes.deleteAriaDetail', { title: note.title }) : '' }));
  removeBtn.addEventListener('click', () => {
    if (!confirm(t('notes.removeConfirm'))) return;
    const idx = vault.notes.findIndex(n => n.id === note.id);
    if (idx !== -1) vault.notes.splice(idx, 1);
    markDirty();
    renderNotes();
  });

  topRow.appendChild(titleInput);
  topRow.appendChild(removeBtn);

  const bodyInput = document.createElement('textarea');
  bodyInput.className = 'note-body';
  bodyInput.placeholder = t('notes.bodyPlaceholder');
  bodyInput.setAttribute('aria-label', t('notes.bodyAria'));
  bodyInput.value = note.body || '';
  bodyInput.addEventListener('input', () => {
    note.body = bodyInput.value;
    note.updatedAt = new Date().toISOString();
    markDirty();
  });

  const swatches = document.createElement('div');
  swatches.className = 'note-color-swatches';
  NOTE_COLORS.forEach(color => {
    const swatch = document.createElement('button');
    swatch.type = 'button';
    swatch.className = 'note-color-swatch' + (note.color === color ? ' selected' : '');
    swatch.style.background = color;
    swatch.setAttribute('aria-label', t('notes.setColorAria'));
    swatch.addEventListener('click', () => {
      note.color = color;
      card.style.background = color;
      markDirty();
      swatches.querySelectorAll('.note-color-swatch').forEach(s => s.classList.remove('selected'));
      swatch.classList.add('selected');
    });
    swatches.appendChild(swatch);
  });

  card.appendChild(topRow);
  card.appendChild(bodyInput);
  card.appendChild(swatches);
  return card;
}

addNoteBtn.addEventListener('click', () => {
  vault.notes.unshift(newNote());
  markDirty();
  renderNotes();
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
    empty.textContent = t('chat.empty');
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
    announce(err.message || t('chat.sendFailed'));
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
    adminMessageCountEl.textContent = t(messageCount === 1 ? 'admin.messageCountOne' : 'admin.messageCountMany', { count: messageCount });
  } catch (err) {
    announce(err.message || t('admin.loadUsersFailed'));
  }
  try {
    const { activity } = await Api.getAdminActivity();
    renderAdminActivity(activity);
  } catch (err) {
    announce(err.message || t('admin.loadActivityFailed'));
  }
}

function renderAdminUsers(users) {
  adminUsersEl.innerHTML = '';
  if (users.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'admin-empty';
    empty.textContent = t('admin.noUsers');
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
    ? t('admin.lastLogin', { date: new Date(u.lastLoginAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) })
    : t('admin.neverLoggedIn');
  metaEl.textContent = t('admin.joinedMeta', { joined, lastLogin, noVault: u.hasVaultData ? '' : t('admin.noVaultYet') });
  info.appendChild(nameEl);
  info.appendChild(metaEl);
  row.appendChild(info);

  const isSelf = u.username.toLowerCase() === currentUserEl.textContent.toLowerCase();
  if (isSelf) {
    const badge = document.createElement('span');
    badge.className = 'admin-you-badge';
    badge.textContent = t('admin.youBadge');
    row.appendChild(badge);
  } else {
    const delBtn = document.createElement('button');
    delBtn.className = 'icon-btn danger';
    delBtn.textContent = '✕';
    delBtn.title = t('admin.deleteUserTitle');
    delBtn.setAttribute('aria-label', t('admin.deleteUserAria', { username: u.username }));
    delBtn.addEventListener('click', async () => {
      if (!confirm(t('admin.deleteUserConfirm', { username: u.username }))) return;
      try {
        await Api.deleteAdminUser(u.id);
        announce(t('admin.deletedUserAnnounce', { username: u.username }));
        loadAdminData();
      } catch (err) {
        announce(err.message || t('admin.deleteUserFailed'));
      }
    });
    row.appendChild(delBtn);
  }
  return row;
}

const ACTIVITY_LABELS = {
  login: e => t('activity.login', { user: e.username }),
  login_failed: e => t('activity.loginFailed', { user: e.username }),
  register: e => t('activity.register', { user: e.username }),
  user_deleted: e => t('activity.userDeleted', { user: e.username, by: e.deletedBy || t('admin.adminFallback') }),
  chat_cleared: e => t('activity.chatCleared', { user: e.username }),
  password_changed: e => t('activity.passwordChanged', { user: e.username })
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
    empty.textContent = t('admin.noActivity');
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
  if (!confirm(t('admin.clearChatConfirm'))) return;
  try {
    await Api.clearChatHistory();
    chatMessages = [];
    lastMessageTime = null;
    renderFullChatHistory();
    announce(t('admin.chatClearedAnnounce'));
    loadAdminData();
  } catch (err) {
    announce(err.message || t('admin.clearChatFailed'));
  }
});

function markDirty() {
  dirty = true;
  saveStatusEl.textContent = t('common.unsavedChanges');
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveVaultNow, 1200);
}

async function saveVaultNow() {
  if (!dirty || !encKey) return;
  try {
    saveStatusEl.textContent = t('common.saving');
    const { iv, blob } = await encryptVaultFn(vault, encKey);
    await Api.saveVault(iv, blob);
    dirty = false;
    saveStatusEl.textContent = t('common.saved');
    setTimeout(() => { if (!dirty) saveStatusEl.textContent = ''; }, 1500);
  } catch (e) {
    saveStatusEl.textContent = t('common.saveFailed');
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

// Registers the app-shell service worker (see sw.js) so the app installs
// as a PWA and launches reliably. It only ever caches static shell
// files — vault/auth/chat requests always go straight to the network.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch((err) => {
      console.warn('Service worker registration failed:', err);
    });
  });
}
