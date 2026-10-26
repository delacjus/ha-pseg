"use strict";

// Render the shipped card with synthetic HA states; no browser or network needed.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const SOURCE = fs.readFileSync(
  path.join(__dirname, "..", "custom_components", "pseg", "frontend", "pseg-energy-card.js"),
  "utf8"
);
const LEGACY_KEY = "pseg_last_valid_entity";

function environment({ denyStorage = false } = {}) {
  const stored = new Map([[LEGACY_KEY, JSON.stringify(reading("11112222"))]]);
  let Card;
  class Element {
    attachShadow() {
      this.shadowRoot = { innerHTML: "", getElementById: () => null };
    }
  }
  vm.runInNewContext(SOURCE, {
    HTMLElement: Element,
    customElements: { get: () => null, define: (_name, type) => { Card = type; } },
    window: { customCards: [] },
    localStorage: {
      removeItem(key) {
        if (denyStorage) throw new Error("Storage denied");
        stored.delete(key);
      },
      getItem() { assert.fail("The card must not read persistent account data"); },
      setItem() { assert.fail("The card must not persist account data"); },
    },
    console: { error: (...args) => assert.fail(`Unexpected render error: ${args}`) },
  });
  return { Card, stored };
}

function reading(meter, { state = "10", cost = 2.5 } = {}) {
  const date = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  return {
    state,
    attributes: {
      meter: `Meter #${meter}`,
      latest_date: date,
      latest_cost: cost,
      history_14d: [{ date, kwh: 10 }],
    },
  };
}

function card(Card, entity, states) {
  const instance = new Card();
  instance.setConfig({ entity });
  instance.hass = { states };
  return instance;
}

test("an unavailable account never displays another card's readings or the legacy cache", () => {
  const { Card, stored } = environment();
  const a = card(Card, "sensor.a", { "sensor.a": reading("11112222") });
  assert.match(a.shadowRoot.innerHTML, /Meter \.\.\.2222/);
  const b = card(Card, "sensor.b", { "sensor.b": { state: "unavailable", attributes: {} } });
  assert.match(b.shadowRoot.innerHTML, /Waiting for initial data sync/);
  assert.doesNotMatch(b.shadowRoot.innerHTML, /2222/);
  assert.equal(stored.has(LEGACY_KEY), false);
});

test("a missing configured entity never falls back to another account's default entity", () => {
  const { Card } = environment();
  const b = card(Card, "sensor.b", {
    "sensor.pseg_electricity_consumption": reading("11112222"),
    "sensor.pseg_electricity_yesterday": reading("33334444"),
  });
  assert.match(b.shadowRoot.innerHTML, /Waiting for initial data sync/);
  assert.doesNotMatch(b.shadowRoot.innerHTML, /2222|4444/);
});

test("reconfiguring a card cannot retain the previous entity's readings", () => {
  const { Card } = environment();
  const instance = card(Card, "sensor.a", { "sensor.a": reading("11112222") });
  instance.setConfig({ entity: "sensor.b" });
  assert.match(instance.shadowRoot.innerHTML, /Waiting for initial data sync/);
  assert.doesNotMatch(instance.shadowRoot.innerHTML, /2222/);
});

test("removing an entity on a new HA state clears its old display", () => {
  const { Card } = environment();
  const instance = card(Card, "sensor.a", { "sensor.a": reading("11112222") });
  instance.hass = { states: {} };
  assert.match(instance.shadowRoot.innerHTML, /Waiting for initial data sync/);
  assert.doesNotMatch(instance.shadowRoot.innerHTML, /2222/);
});

test("HA's restored readings remain visible with an authentication warning", () => {
  const { Card } = environment();
  const instance = card(Card, "sensor.a", {
    "sensor.a": reading("11112222", { state: "unavailable" }),
  });
  assert.match(instance.shadowRoot.innerHTML, /Meter \.\.\.2222/);
  assert.match(instance.shadowRoot.innerHTML, /Re-authentication required/);
});

test("a zero estimated rate remains zero in the card", () => {
  const { Card } = environment();
  const instance = card(Card, "sensor.a", {
    "sensor.a": reading("11112222", { cost: 0 }),
    "input_boolean.pseg_display_dollars": { state: "on" },
  });
  assert.doesNotMatch(instance.shadowRoot.innerHTML, /class="stat-val">(?:0\.25|2\.47)</);
  assert.match(instance.shadowRoot.innerHTML, /class="stat-val">0\.00</);
});

test("denied browser storage does not prevent rendering", () => {
  const { Card } = environment({ denyStorage: true });
  const instance = card(Card, "sensor.a", { "sensor.a": reading("11112222") });
  assert.match(instance.shadowRoot.innerHTML, /Meter \.\.\.2222/);
});
