#!/usr/bin/env python3
"""Password-gate the site: encrypt every page in _src/ into a publishable page at the root.

Edit pages in _src/ (git-ignored, never published), then run:

    python3 tools/protect.py            # password from SITE_PASSWORD, default "123"

Each output page holds only AES-256-GCM ciphertext plus a small unlock form. The key is
derived from the password with PBKDF2-SHA256; once a visitor unlocks, the derived key is
remembered in their browser so other pages open without asking again.

This keeps casual visitors out. It is not strong security with a short password: anyone
with the ciphertext can guess "123" offline, and images/videos/scripts stay public.
"""
import base64
import json
import os
import pathlib
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "_src"
ITERATIONS = 250_000

GATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>States News Service</title>
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<style>
@font-face { font-family: 'Newsreader'; font-display: swap; src: url(uploads/fonts/newsreader-normal-latin.woff2) format('woff2'); }
@font-face { font-family: 'Public Sans'; font-display: swap; src: url(uploads/fonts/publicsans-normal-latin.woff2) format('woff2'); }
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; }
body { display: flex; align-items: center; justify-content: center; padding: 16px;
  background: #f5f7fb; color: #0b1f3a; font-family: 'Public Sans', system-ui, sans-serif; }
form { width: 100%; max-width: 360px; background: #fff; border: 1px solid #dce3ec;
  border-radius: 12px; padding: 32px 28px; box-shadow: 0 8px 30px rgba(11,31,58,.06); }
h1 { font-family: 'Newsreader', serif; font-weight: 400; font-size: 28px; margin: 0 0 6px; }
p { margin: 0 0 22px; color: #5a6b81; font-size: 14px; }
input { width: 100%; font: inherit; font-size: 16px; padding: 11px 12px; color: #0b1f3a;
  border: 1px solid #dce3ec; border-radius: 8px; outline: none; }
input:focus { border-color: #3b6fc4; box-shadow: 0 0 0 3px #eaf0f9; }
button { margin-top: 12px; width: 100%; font: inherit; font-size: 15px; font-weight: 600;
  padding: 11px; border: 0; border-radius: 8px; background: #0b1f3a; color: #fff; cursor: pointer; }
button:disabled { opacity: .6; cursor: default; }
.err { min-height: 20px; margin: 10px 0 0; font-size: 13px; color: #b3261e; }
</style>
</head>
<body>
<form id="gate" hidden>
  <h1>States News Service</h1>
  <p>This site is private. Enter the password to continue.</p>
  <input id="pw" type="password" autocomplete="current-password" aria-label="Password" placeholder="Password" required>
  <button id="go" type="submit">Enter</button>
  <div class="err" id="err" role="alert"></div>
</form>
<script>
(function () {
  var P = __PAYLOAD__;
  var STORE = 'sns-gate-key';
  var te = new TextEncoder();
  function b64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }
  function get() { try { return localStorage.getItem(STORE); } catch (e) { return null; } }
  function put(v) { try { localStorage.setItem(STORE, v); } catch (e) {} }
  function drop() { try { localStorage.removeItem(STORE); } catch (e) {} }

  function open(raw) {
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt'])
      .then(function (key) { return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(P.iv) }, key, b64(P.ct)); })
      .then(function (buf) {
        var html = new TextDecoder().decode(buf);
        document.open(); document.write(html); document.close();
      });
  }
  function derive(pw) {
    return crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits'])
      .then(function (base) {
        return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64(P.salt), iterations: P.iter }, base, 256);
      });
  }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
  function unhex(h) { return new Uint8Array(h.match(/../g).map(function (x) { return parseInt(x, 16); })); }

  var form = document.getElementById('gate'), pw = document.getElementById('pw'),
      go = document.getElementById('go'), err = document.getElementById('err');
  function ask() { form.hidden = false; pw.focus(); }

  if (!window.crypto || !crypto.subtle) { form.hidden = false; err.textContent = 'This browser cannot open the site.'; go.disabled = true; return; }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    err.textContent = ''; go.disabled = true;
    var bits;
    derive(pw.value)
      .then(function (b) { bits = b; return open(b); })
      .then(function () { put(P.salt + ':' + hex(bits)); })
      .catch(function () { go.disabled = false; pw.select(); err.textContent = 'Incorrect password.'; });
  });

  var saved = get();
  if (saved && saved.split(':')[0] === P.salt) {
    open(unhex(saved.split(':')[1])).catch(function () { drop(); ask(); });
  } else {
    ask();
  }
})();
</script>
</body>
</html>
"""


def main():
    password = os.environ.get("SITE_PASSWORD", "123")
    pages = sorted(SRC.glob("*.html"))
    if not pages:
        sys.exit(f"no pages found in {SRC}")

    salt = os.urandom(16)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(
        password.encode("utf-8")
    )
    aes = AESGCM(key)
    enc = lambda b: base64.b64encode(b).decode("ascii")

    for page in pages:
        iv = os.urandom(12)
        ct = aes.encrypt(iv, page.read_bytes(), None)
        payload = json.dumps({"salt": enc(salt), "iv": enc(iv), "ct": enc(ct), "iter": ITERATIONS})
        (ROOT / page.name).write_text(GATE.replace("__PAYLOAD__", payload), encoding="utf-8")
        print(f"protected {page.name}")


if __name__ == "__main__":
    main()
