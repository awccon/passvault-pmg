# PassVault — Your Self-Hosted Password Book

A personal password manager you run yourself. Supports multiple separate
user accounts. Built so that **the server never sees your master
password and never sees your decrypted data** — everything is encrypted
and decrypted in your browser.

## How the security works (read this once)

- When you register, your browser turns your master password into two
  completely separate keys using PBKDF2 (210,000 iterations):
  - an **auth key** — sent to the server, hashed again with bcrypt, and
    used only to check your password at login.
  - an **encryption key** — never leaves your browser, ever. It's held
    in memory only for the current session and is used to encrypt/decrypt
    your vault with AES-256-GCM.
- The server's database (`data/users.json`, `data/vaults.json`) only
  contains: your username, a random salt, a bcrypt hash of the auth key,
  and an opaque encrypted blob. None of that is usable to recover your
  master password or your vault contents.
- **There is no password reset.** If you forget your master password,
  your data is unrecoverable by design — that's the tradeoff for true
  zero-knowledge encryption. Write your master password down somewhere
  safe (e.g. on paper, in a safe) — just not in this app itself.
- Refreshing the page clears the encryption key from memory, so you'll
  need to re-enter your master password each time you open the app.
  This is intentional.

## Running it locally

Requires Node.js 18+.
.
```bash
cd passvault
npm install
SESSION_SECRET="$(openssl rand -hex 32)" npm start
```

Then open http://localhost:3000

`SESSION_SECRET` signs your login session cookie. Generate a random one
and keep it the same across restarts (otherwise everyone gets logged
out whenever you restart the server). Store it as an environment
variable, not in the code.

## Deploying on your own VPS

This walks through a from-scratch deploy on a fresh Ubuntu VPS (Hetzner,
DigitalOcean, etc.) with your own domain, ending with the app running at
`https://vault.yourdomain.com`. Replace `vault.yourdomain.com` and
`your-server-ip` below with your actual domain/IP throughout.

### 1. Spin up the VPS

Create an account with Hetzner Cloud or DigitalOcean. Launch the
cheapest Ubuntu 24.04 instance (Hetzner CX22 ~€4/mo, or a DigitalOcean
$6/mo droplet). Pick a datacenter near you, and set up SSH key login
during creation instead of a password.

### 2. Point your domain at it

In your domain's DNS settings, add an **A record** for a subdomain
(e.g. `vault`) pointing to the VPS's IP address:

```
Type: A
Name: vault
Value: your-server-ip
```

DNS can take a few minutes to a few hours to propagate.

### 3. Log in and do basic hardening

SSH in as root, then:

```bash
adduser deploy
usermod -aG sudo deploy
ufw allow OpenSSH
ufw allow 80
ufw allow 443
ufw enable
```

Then edit `/etc/ssh/sshd_config`, set `PermitRootLogin no` and
`PasswordAuthentication no`, and restart ssh (`systemctl restart ssh`).
Log back in as `deploy` from here on.

### 4. Install Node.js and pm2

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt install -y nodejs
sudo npm install -g pm2
```

`pm2` keeps the app running and restarts it on crash or reboot.

### 5. Upload and install the app

From your own machine:

```bash
scp -r passvault deploy@your-server-ip:~/
```

(or clone it from a private git repo instead). Then on the server:

```bash
cd passvault
npm install --production
```

### 6. Set the session secret and start with pm2

```bash
openssl rand -hex 32   # copy the output
SESSION_SECRET="<paste-the-generated-value>" COOKIE_SECURE=true \
  pm2 start server.js --name passvault
pm2 save
pm2 startup   # then run the command it prints
```

Keep `SESSION_SECRET` the same forever — changing it logs everyone out.

### 7. Put Caddy in front for free HTTPS

```bash
sudo apt install -y caddy
```

Edit `/etc/caddy/Caddyfile` so it contains just:

```
vault.yourdomain.com {
    reverse_proxy localhost:3000
}
```

```bash
sudo systemctl restart caddy
```

Caddy automatically fetches and renews a free TLS certificate for your
domain — no manual certificate setup needed.

### 8. Test and back up

Visit `https://vault.yourdomain.com`, register your account, and
confirm login/save/reload all work. Then set up a simple cron job or
script to periodically copy the `passvault/data` folder somewhere safe
(another machine, encrypted cloud storage) — it's the only copy of
your encrypted vault.

## Using the app

- **Register** with a username and a strong master password (this is
  the *only* password you need to remember — everything else lives
  inside the vault).
- Click **+ Add email address** to create a new header/section.
- Each section has:
  - An editable **email address** as the header.
  - A **username** field.
  - Up to **5 passwords**, each with its own label (e.g. "Password 1",
    "Recovery code") and a show/hide toggle.
  - A **Key Questions** area for security questions and answers —
    add as many as you like.
- Changes autosave about a second after you stop typing (see the
  "Saving…" indicator at the top right).

## Limitations / things to consider adding later

- No password strength meter or generator (can be added).
- No import/export yet — could add an encrypted export/import feature.
- No account recovery / multi-device master password rotation flow.
- Single flat vault per user (not encrypted field-by-field) — simpler,
  but means the whole vault decrypts/encrypts together.
- No rate limiting on login attempts — worth adding
  (e.g. `express-rate-limit`) if you expose this beyond your home network.
