// api.js — thin wrapper around fetch for the server's HTTP API.
const Api = {
  async getSalt(username) {
    const r = await fetch('/api/salt/' + encodeURIComponent(username));
    return r.json();
  },
  async register(username, salt, authProof) {
    const r = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, salt, authProof })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Registration failed');
    return data;
  },
  async login(username, authProof) {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, authProof })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Login failed');
    return data;
  },
  async logout() {
    await fetch('/api/logout', { method: 'POST' });
  },
  async me() {
    const r = await fetch('/api/me');
    return r.json();
  },
  async getVault() {
    const r = await fetch('/api/vault');
    if (!r.ok) throw new Error('Could not load vault');
    return r.json();
  },
  async saveVault(iv, blob) {
    const r = await fetch('/api/vault', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iv, blob })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Save failed');
    return data;
  },
  async getMessages(since) {
    const url = '/api/messages' + (since ? ('?since=' + encodeURIComponent(since)) : '');
    const r = await fetch(url);
    if (!r.ok) throw new Error('Could not load messages');
    return r.json();
  },
  async sendMessage(text) {
    const r = await fetch('/api/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Failed to send message');
    return data;
  }
};
window.Api = Api;
