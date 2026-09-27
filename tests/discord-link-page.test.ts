import assert from "node:assert/strict";
import { test } from "node:test";
import { Script } from "node:vm";
import {
  discordLinkPageJavaScript,
  renderDiscordLinkPage,
} from "../src/discord-link-page.js";

test("the Discord connection page keeps the ticket in the URL fragment", () => {
  assert.doesNotThrow(() => new Script(discordLinkPageJavaScript));
  assert.match(discordLinkPageJavaScript, /window\.location\.hash/);
  assert.match(discordLinkPageJavaScript, /history\.replaceState/);
  const html = renderDiscordLinkPage();
  assert.match(html, /<script type="module" src="\/assets\/discord-link\.js"><\/script>/);
  assert.doesNotMatch(html, /<script[^>]*>\s*[^<]/);
});
