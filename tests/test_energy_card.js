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

function twoAccounts() {
  const states = {
    "sensor.pseg_electricity_consumption": reading("11112222"),
    "sensor.pseg_connection_status": { state: "auth_required", attributes: {} },
    "sensor.pseg_electricity_consumption_2": reading("33334444"),
    "sensor.pseg_connection_status_2": { state: "connected", attributes: {} },
  };
  const entities = {};
  for (const [id, device] of [
    ["sensor.pseg_electricity_consumption", "dev1"],
    ["sensor.pseg_connection_status", "dev1"],
    ["sensor.pseg_electricity_consumption_2", "dev2"],
    ["sensor.pseg_connection_status_2", "dev2"],
  ]) {
    entities[id] = { entity_id: id, device_id: device };
  }
  return { states, entities };
}

function cardWithRegistry(Card, config, hass) {
  const instance = new Card();
  instance.setConfig(config);
  instance.hass = hass;
  return instance;
}

test("a second account's card uses its own connection status, not the first account's", () => {
  const { Card } = environment();
  const hass = twoAccounts();
  const second = cardWithRegistry(Card, { entity: "sensor.pseg_electricity_consumption_2" }, hass);
  assert.match(second.shadowRoot.innerHTML, /Meter \.\.\.4444/);
  assert.doesNotMatch(second.shadowRoot.innerHTML, /Re-authentication required/);
  const first = cardWithRegistry(Card, { entity: "sensor.pseg_electricity_consumption" }, hass);
  assert.match(first.shadowRoot.innerHTML, /Re-authentication required/);
});

test("a card whose account has no status sensor never borrows another account's", () => {
  const { Card } = environment();
  const hass = twoAccounts();
  delete hass.states["sensor.pseg_connection_status_2"];
  delete hass.entities["sensor.pseg_connection_status_2"];
  const second = cardWithRegistry(Card, { entity: "sensor.pseg_electricity_consumption_2" }, hass);
  assert.doesNotMatch(second.shadowRoot.innerHTML, /Re-authentication required/);
});

test("a registry that arrives after the first render re-resolves the account's status", () => {
  const { Card } = environment();
  const { states, entities } = twoAccounts();
  const second = cardWithRegistry(Card, { entity: "sensor.pseg_electricity_consumption_2" }, { states });
  assert.match(second.shadowRoot.innerHTML, /Re-authentication required/);
  second.hass = { states, entities };
  assert.doesNotMatch(second.shadowRoot.innerHTML, /Re-authentication required/);
});

test("without the entity registry the card keeps the fixed status sensor", () => {
  const { Card } = environment();
  const { states } = twoAccounts();
  const instance = card(Card, "sensor.pseg_electricity_consumption", states);
  assert.match(instance.shadowRoot.innerHTML, /Re-authentication required/);
});

test("an explicit connection_status_entity still wins over the account lookup", () => {
  const { Card } = environment();
  const hass = twoAccounts();
  const second = cardWithRegistry(Card, {
    entity: "sensor.pseg_electricity_consumption_2",
    connection_status_entity: "sensor.pseg_connection_status",
  }, hass);
  assert.match(second.shadowRoot.innerHTML, /Re-authentication required/);
});

test("the next update time comes from the card's own account", () => {
  const { Card } = environment();
  const hass = twoAccounts();
  hass.states["sensor.pseg_next_update"] = { state: "2026-01-01T09:00:00Z", attributes: {} };
  hass.states["sensor.pseg_next_update_2"] = { state: "2026-01-01T17:00:00Z", attributes: {} };
  hass.entities["sensor.pseg_next_update"] = { entity_id: "sensor.pseg_next_update", device_id: "dev1" };
  hass.entities["sensor.pseg_next_update_2"] = { entity_id: "sensor.pseg_next_update_2", device_id: "dev2" };
  const config = (entity) => ({ entity, show_next_update: true });
  const first = cardWithRegistry(Card, config("sensor.pseg_electricity_consumption"), hass);
  const second = cardWithRegistry(Card, config("sensor.pseg_electricity_consumption_2"), hass);
  assert.match(first.shadowRoot.innerHTML, /↻/);
  assert.match(second.shadowRoot.innerHTML, /↻/);
  assert.notEqual(
    first.shadowRoot.innerHTML.match(/↻ [^<"]*/)[0],
    second.shadowRoot.innerHTML.match(/↻ [^<"]*/)[0],
  );
});
