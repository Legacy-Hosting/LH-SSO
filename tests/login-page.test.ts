import assert from "node:assert/strict";
import { test } from "node:test";
import { Script } from "node:vm";
import { loginPageJavaScript, renderLoginPage } from "../src/login-page.js";

test("the passkey login page uses external parseable JavaScript", () => {
  assert.doesNotThrow(() => new Script(loginPageJavaScript));
  const html = renderLoginPage("interaction_uid_123456");
  assert.match(html, /<script type="module" src="\/assets\/login\.js"><\/script>/);
  assert.doesNotMatch(html, /<script[^>]*>\s*[^<]/);
});
