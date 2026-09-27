export function renderServicePage() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#0b0c10">
  <meta name="color-scheme" content="dark">
  <meta name="description" content="Secure identity and single sign-on for Legacy Hosting services.">
  <meta name="robots" content="noindex, nofollow, noarchive">
  <link rel="canonical" href="https://auth.legacyhosting.xyz/">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <link rel="shortcut icon" href="/favicon.ico">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png">
  <link rel="manifest" href="/site.webmanifest">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="Legacy Hosting">
  <meta property="og:title" content="Legacy Hosting Identity">
  <meta property="og:description" content="Passkey-protected identity and single sign-on across Legacy Hosting services.">
  <meta property="og:url" content="https://auth.legacyhosting.xyz/">
  <meta property="og:image" content="https://auth.legacyhosting.xyz/social-card.png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="Legacy Hosting Identity">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="Legacy Hosting Identity">
  <meta name="twitter:description" content="Passkey-protected identity and single sign-on across Legacy Hosting services.">
  <meta name="twitter:image" content="https://auth.legacyhosting.xyz/social-card.png">
  <title>Identity · Legacy Hosting</title>
  <link rel="stylesheet" href="/assets/login.css">
</head>
<body>
  <main class="login-card">
    <div class="mark">L</div>
    <p class="eyebrow">Legacy Hosting SSO</p>
    <h1>One secure identity</h1>
    <p class="intro">Central passkey-protected sign-in for the Legacy Hosting control panel and staff services.</p>
    <div class="status-pill"><i></i>Identity service operational</div>
    <p class="help">Sign-in starts automatically when you open a protected Legacy Hosting service.</p>
  </main>
</body>
</html>`;
}
