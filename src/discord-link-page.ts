export function renderDiscordLinkPage() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Connect Discord · Legacy Hosting</title>
  <link rel="stylesheet" href="/assets/discord-link.css">
  <script type="module" src="/assets/discord-link.js"></script>
</head>
<body>
  <main class="link-card">
    <div class="mark">L</div>
    <p class="eyebrow">Legacy Hosting SSO</p>
    <h1>Connect your Discord account</h1>
    <p class="intro">Confirm the connection with the passkey already registered to your Legacy Hosting account.</p>
    <form id="link-form">
      <label for="email">Email <span>Optional with a discoverable passkey</span></label>
      <input id="email" name="email" type="email" autocomplete="username webauthn" placeholder="you@example.com">
      <button id="continue" type="submit">Connect with passkey</button>
    </form>
    <section id="success" class="success" hidden>
      <strong>Discord connected</strong>
      <p>Your staff access is now synchronized. You can close this page.</p>
    </section>
    <p id="error" class="error" role="alert" hidden></p>
    <p class="help">This link expires after ten minutes and can only be used once. Legacy Hosting never links Discord accounts by display name or email alone.</p>
  </main>
</body>
</html>`;
}

export const discordLinkPageCss = `
:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #0b0c10; color: #f3f3f7; }
* { box-sizing: border-box; }
body { min-height: 100vh; margin: 0; display: grid; place-items: center; padding: 24px; background: radial-gradient(circle at 50% 0%, #211d3b 0, #0b0c10 42%); }
.link-card { width: min(460px, 100%); padding: 38px; border: 1px solid #292a33; border-radius: 16px; background: #13141a; box-shadow: 0 30px 90px rgba(0,0,0,.36); }
.mark { width: 44px; height: 44px; display: grid; place-items: center; border-radius: 12px; background: #7157f6; font-weight: 800; font-size: 20px; }
.eyebrow { margin: 24px 0 8px; color: #a99aff; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; }
h1 { margin: 0; font-size: 28px; letter-spacing: -.03em; }
.intro { margin: 10px 0 27px; color: #999baa; line-height: 1.55; font-size: 14px; }
form { display: grid; gap: 12px; }
label { font-size: 12px; font-weight: 650; }
label span { float: right; color: #737583; font-weight: 400; }
input, button { width: 100%; min-height: 46px; border-radius: 9px; font: inherit; }
input { padding: 0 13px; color: #f3f3f7; border: 1px solid #30313b; background: #0d0e13; outline: none; }
input:focus { border-color: #806cff; box-shadow: 0 0 0 3px rgba(128,108,255,.15); }
button { margin-top: 7px; border: 0; color: white; background: #7157f6; font-weight: 700; cursor: pointer; }
button:disabled { cursor: wait; opacity: .7; }
.error, .success { margin: 18px 0 0; padding: 13px 14px; border-radius: 9px; font-size: 12px; line-height: 1.45; }
.error { border: 1px solid rgba(239,92,105,.38); color: #ffafb6; background: rgba(239,92,105,.09); }
.success { border: 1px solid rgba(47,211,140,.35); color: #a7f3d0; background: rgba(47,211,140,.08); }
.success p { margin: 4px 0 0; color: #8fc8ad; }
.help { margin: 25px 0 0; padding-top: 20px; border-top: 1px solid #272832; color: #737583; font-size: 11px; line-height: 1.55; }
@media (max-width: 520px) { body { padding: 16px; } .link-card { padding: 28px 23px; } label span { display: block; float: none; margin-top: 3px; } }
`;

export const discordLinkPageJavaScript = String.raw`
const form = document.querySelector('#link-form');
const email = document.querySelector('#email');
const button = document.querySelector('#continue');
const errorBox = document.querySelector('#error');
const successBox = document.querySelector('#success');
const fragment = new URLSearchParams(window.location.hash.slice(1));
const ticket = fragment.get('ticket') || '';
history.replaceState(null, '', window.location.pathname);

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const bytes = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
  return bytes.buffer;
}

function encodeBase64Url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function publicKeyOptions(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((credential) => ({
      ...credential,
      id: decodeBase64Url(credential.id),
    })),
  };
}

function responseJson(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      authenticatorData: encodeBase64Url(credential.response.authenticatorData),
      signature: encodeBase64Url(credential.response.signature),
      userHandle: credential.response.userHandle
        ? encodeBase64Url(credential.response.userHandle)
        : null,
    },
  };
}

async function jsonRequest(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || 'authentication_failed');
  return payload.data;
}

const messages = {
  authentication_failed: 'The account or passkey could not be verified.',
  invalid_or_expired_link: 'This Discord connection link is invalid, expired, or already used. Run /lh-link again in Discord.',
  discord_link_conflict: 'This Discord or Legacy Hosting account is already connected to a different account. Contact support if this is unexpected.',
  discord_staff_role_required: 'Your eligible Discord staff role is no longer active. Ask an administrator to verify your roles.',
};

if (!/^[A-Za-z0-9_-]{43}$/.test(ticket)) {
  form.hidden = true;
  errorBox.textContent = messages.invalid_or_expired_link;
  errorBox.hidden = false;
}

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  button.disabled = true;
  errorBox.hidden = true;
  try {
    const started = await jsonRequest(
      '/discord/link/passkey/options',
      email.value ? { ticket, email: email.value } : { ticket },
    );
    const credential = await navigator.credentials.get({
      publicKey: publicKeyOptions(started.options),
    });
    if (!credential) throw new Error('authentication_cancelled');
    await jsonRequest('/discord/link/passkey/verify', {
      ticket,
      challengeId: started.challengeId,
      response: responseJson(credential),
    });
    form.hidden = true;
    successBox.hidden = false;
  } catch (error) {
    const key = error?.message || '';
    errorBox.textContent = error?.name === 'NotAllowedError'
      ? 'The passkey prompt was cancelled.'
      : (messages[key] || 'The Discord account could not be connected. Please try again.');
    errorBox.hidden = false;
    button.disabled = false;
  }
});
`;
