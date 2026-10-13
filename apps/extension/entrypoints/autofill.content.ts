/**
 * Autofill content script. Discovers credential inputs, offers a shadow-DOM
 * suggestions menu (credentials themselves are fetched per-selection from the
 * background, which re-checks the tab origin), fills forms, and prompts to
 * save new logins on submit. Never holds keys — everything is messaging.
 */
import type {
  BackgroundRequest,
  BackgroundResponse,
  CredentialsData,
  GeneratedData,
  MatchEntry,
  StatusData,
  VaultOption,
} from "../lib/messages";

async function send<T>(req: BackgroundRequest): Promise<T> {
  const res = (await chrome.runtime.sendMessage(req)) as
    | BackgroundResponse
    | undefined;
  if (!res) throw new Error("Kleidion background unavailable");
  if (!res.ok) throw new Error(res.error);
  return res.data as T;
}

const HOST = location.hostname;

function isCredentialField(el: Element): el is HTMLInputElement {
  if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return false;
  if (el.type === "password") return true;
  if (el.type === "email") return true;
  const hint = `${el.name} ${el.id} ${el.autocomplete ?? ""} ${el.placeholder ?? ""}`.toLowerCase();
  return el.type === "text" && /user|email|login|account/.test(hint);
}

function credentialFields(root: ParentNode = document): HTMLInputElement[] {
  return Array.from(root.querySelectorAll("input")).filter(isCredentialField);
}

function setNativeValue(el: HTMLInputElement, value: string): void {
  const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  if (desc?.set) desc.set.call(el, value);
  else el.value = value;
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

// ---------------------------------------------------------------- menu UI

let menuHost: HTMLElement | null = null;
let shadow: ShadowRoot | null = null;
/** Bumped by every menu open, so a stale blur timer cannot close a newer menu. */
let menuSeq = 0;

function ensureMenu(): { host: HTMLElement; root: ShadowRoot } {
  menuSeq++;
  if (menuHost && shadow) return { host: menuHost, root: shadow };
  menuHost = document.createElement("div");
  menuHost.id = "kleidion-autofill";
  menuHost.style.cssText = "all: initial; position: fixed; z-index: 2147483647;";
  shadow = menuHost.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <style>
      .menu { position: fixed; min-width: 240px; max-width: 340px; background: oklch(0.21 0.025 265);
        border: 1px solid oklch(0.32 0.03 265); border-radius: 8px; overflow: hidden;
        font: 13px/1.4 system-ui, sans-serif; color: oklch(0.93 0.01 265);
        box-shadow: 0 8px 24px rgba(0,0,0,.45); }
      .item { display: flex; justify-content: space-between; gap: 10px; padding: 8px 12px; cursor: pointer; }
      .item:hover, .item.active { background: oklch(0.26 0.03 265); }
      .item .sub { color: oklch(0.68 0.02 265); font-size: 11px; }
      .empty { padding: 8px 12px; color: oklch(0.68 0.02 265); }
    </style>`;
  document.documentElement.appendChild(menuHost);
  return { host: menuHost, root: shadow };
}

function closeMenu(): void {
  menuHost?.remove();
  menuHost = null;
  shadow = null;
}

function openMenu(
  anchor: HTMLElement,
  entries: MatchEntry[],
  pick: (e: MatchEntry) => void,
  generate?: () => void,
): void {
  closeMenu();
  const { root } = ensureMenu();
  const box = document.createElement("div");
  box.className = "menu";
  const rect = anchor.getBoundingClientRect();
  box.style.left = `${Math.max(4, Math.min(rect.left, innerWidth - 350))}px`;
  box.style.top = `${Math.max(4, rect.top - 8 - (entries.length + (generate ? 1 : 0)) * 42)}px`;
  if (entries.length === 0) {
    box.innerHTML = '<div class="empty">No saved logins here</div>';
  } else {
    for (const entry of entries) {
      const row = document.createElement("div");
      row.className = "item";
      const name = document.createElement("div");
      name.textContent = entry.title;
      const sub = document.createElement("div");
      sub.className = "sub";
      sub.textContent = entry.username;
      row.append(name, sub);
      row.addEventListener("mousedown", (ev) => {
        ev.preventDefault();
        pick(entry);
      });
      box.append(row);
    }
  }
  if (generate) {
    const row = document.createElement("div");
    row.className = "item";
    const name = document.createElement("div");
    name.textContent = "Generate strong password";
    name.style.color = "oklch(0.72 0.15 165)";
    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = "20 chars";
    row.append(name, sub);
    row.addEventListener("mousedown", (ev) => {
      ev.preventDefault();
      generate();
    });
    box.append(row);
  }
  root.appendChild(box);
}

// ---------------------------------------------------------------- filling

async function fillWith(entry: MatchEntry, anchor: HTMLInputElement): Promise<void> {
  try {
    const cred = await send<CredentialsData>({ type: "credentials", itemId: entry.itemId });
    const scope: ParentNode = anchor.form ?? document;
    const fields = credentialFields(scope);
    const passEl = fields.find((f) => f.type === "password");
    const userEl = fields.find((f) => f !== passEl);
    if (userEl) setNativeValue(userEl, cred.username);
    if (passEl) setNativeValue(passEl, cred.password);
    (passEl ?? userEl ?? anchor).focus();
  } catch {
    /* background rejects non-matching origins; ignore silently */
  }
  closeMenu();
}

// ---------------------------------------------------------------- generating

async function generateInto(el: HTMLInputElement): Promise<void> {
  try {
    const { password } = await send<GeneratedData>({ type: "generate" });
    setNativeValue(el, password);
  } catch {
    /* background unavailable */
  }
  closeMenu();
}

// ---------------------------------------------------------- save capture

async function offerSave(form: HTMLFormElement, username: string, password: string): Promise<void> {
  closeMenu(); // a field menu may still be open; the prompt replaces it
  const { root } = ensureMenu();
  const box = document.createElement("div");
  box.className = "menu";
  const rect = form.getBoundingClientRect();
  box.style.left = `${Math.max(4, Math.min(rect.left, innerWidth - 350))}px`;
  box.style.top = `${Math.min(innerHeight - 120, rect.bottom + 6)}px`;

  let vaults: VaultOption[] = [];
  try {
    vaults = (await send<VaultOption[]>({ type: "vaults" })).filter((v) => v.canWrite);
  } catch {
    closeMenu();
    return;
  }
  if (vaults.length === 0) {
    closeMenu();
    return;
  }

  const label = document.createElement("div");
  label.className = "empty";
  label.textContent = `Save login for ${HOST}?`;
  const select = document.createElement("select");
  select.style.cssText =
    "margin:0 12px 8px;padding:4px;border-radius:6px;border:1px solid oklch(0.32 0.03 265);background:oklch(0.16 0.02 265);color:inherit;font:12px system-ui;";
  for (const v of vaults) {
    const opt = document.createElement("option");
    opt.value = v.id;
    opt.textContent = v.name || (v.role === "admin" ? "Owner vault" : "Shared vault");
    select.append(opt);
  }
  const actions = document.createElement("div");
  actions.className = "item";
  const saveBtn = document.createElement("span");
  saveBtn.textContent = "Save";
  saveBtn.style.color = "oklch(0.72 0.15 165)";
  const cancelBtn = document.createElement("span");
  cancelBtn.textContent = "Not now";
  actions.append(saveBtn, cancelBtn);
  box.append(label, select, actions);
  root.appendChild(box);

  cancelBtn.addEventListener("mousedown", (e) => {
    e.preventDefault();
    closeMenu();
  });
  saveBtn.addEventListener("mousedown", (e) => {
    e.preventDefault();
    void send({
      type: "save",
      vaultId: select.value,
      title: document.title || HOST,
      username,
      password,
      hostname: HOST,
    })
      .catch(() => undefined)
      .finally(() => closeMenu());
  });
}

// ------------------------------------------------------------------ main

function main(): void {
  if (window.top !== window) return; // menus only in the top frame

  let entries: MatchEntry[] = [];

  void (async () => {
    try {
      const status = await send<StatusData>({ type: "status" });
      if (!status.unlocked) return;
      entries = await send<MatchEntry[]>({ type: "match", hostname: HOST });
    } catch {
      return; // locked or offline
    }
    wire();
  })();

  function wire(): void {
    document.addEventListener(
      "focusin",
      (e) => {
        const el = e.target;
        if (!(el instanceof HTMLInputElement) || !isCredentialField(el)) return;
        let active = 0;
        const canGenerate = el.type === "password" && el.value === "";
        openMenu(
          el,
          entries,
          (entry) => void fillWith(entry, el),
          canGenerate ? () => void generateInto(el) : undefined,
        );
        const onKeydown = (ev: KeyboardEvent) => {
          if (ev.key === "Escape") {
            closeMenu();
            return;
          }
          if (!entries.length) return;
          if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
            ev.preventDefault();
            active = (active + (ev.key === "ArrowDown" ? 1 : entries.length - 1)) % entries.length;
            const rows = shadow?.querySelectorAll(".item");
            rows?.forEach((r, i) => r.classList.toggle("active", i === active));
          } else if (ev.key === "Enter" && document.querySelector("#kleidion-autofill")) {
            ev.preventDefault();
            void fillWith(entries[active]!, el);
          }
        };
        el.addEventListener("keydown", onKeydown, { once: false });
        // Blur may race a newer menu: moving focus straight to another
        // credential field (e.g. right after a fill) opens that field's menu
        // before this timer fires, so only close our own generation.
        const generation = menuSeq;
        el.addEventListener(
          "blur",
          () => {
            el.removeEventListener("keydown", onKeydown);
            setTimeout(() => {
              if (generation !== menuSeq) return;
              const next = document.activeElement;
              if (next instanceof HTMLInputElement && isCredentialField(next)) return;
              closeMenu(); // allow menu mousedown
            }, 120);
          },
          { once: true },
        );
      },
      true,
    );

    document.addEventListener(
      "submit",
      (e) => {
        const form = e.target;
        if (!(form instanceof HTMLFormElement)) return;
        const passEl = credentialFields(form).find((f) => f.type === "password");
        if (!passEl || !passEl.value) return;
        const userEl = credentialFields(form).find((f) => f !== passEl);
        const username = userEl?.value ?? "";
        const already = entries.some((en) => en.username === username);
        if (!already) void offerSave(form, username, passEl.value);
      },
      true,
    );
  }
}

export default defineContentScript({
  matches: ["https://*/*", "http://localhost/*"],
  runAt: "document_idle",
  main,
});
