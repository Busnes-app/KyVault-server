// Plain DOM, no framework. Pairing runs entirely in this click handler
// (parseServerOrigin, then permissions.request, then the redeem fetch) so the
// browser's user-gesture requirement for permissions.request is met; the
// token this produces is written straight to storage.local and never sent
// through the background worker's message channel.
import { ext } from "../ext";
import { parseServerOrigin } from "../lib/serverUrl";
import { pair } from "../lib/pairing";
import { loadSettings, saveSettings } from "../lib/settings";
import { AUTO_LOCK_MINUTES, parseAutoLockMinutes } from "../../../frontend/src/lib/autoLock";
import type { Request } from "../messages";

const root = document.getElementById("root")!;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

async function notifyBackground(message: Request): Promise<void> {
  await ext.runtime.sendMessage(message);
}

async function render(): Promise<void> {
  root.textContent = "";
  const settings = await loadSettings();
  if (settings.serverOrigin && settings.sessionToken) {
    renderPaired(settings.serverOrigin, settings.deviceName || "this device");
  } else {
    renderPairingForm();
  }
}

function renderPaired(origin: string, deviceName: string): void {
  const status = el("p");
  status.textContent = `Paired with ${origin} as ${deviceName}.`;

  const note = el("p");
  note.textContent = "Unpairing forgets this browser's session. The device stays listed in Security, then Devices, until revoked there.";

  const unpairButton = el("button");
  unpairButton.textContent = "Unpair";
  unpairButton.addEventListener("click", async () => {
    unpairButton.disabled = true;
    await notifyBackground({ type: "unpair" });
    await render();
  });

  root.append(status, note, unpairButton);
}

function renderPairingForm(): void {
  const intro = el("p");
  intro.textContent = "In KyVault, open Security, then Devices, then Pair a device.";

  const serverLabel = el("label");
  serverLabel.textContent = "Server address";
  const serverInput = el("input", { type: "text", placeholder: "https://vault.example.com" });

  const codeLabel = el("label");
  codeLabel.textContent = "Pairing code or PIN";
  const codeInput = el("input", { type: "text", placeholder: "123456" });

  const nameLabel = el("label");
  nameLabel.textContent = "Device name";
  const nameInput = el("input", { type: "text" });
  nameInput.value = "Browser extension";

  const lockLabel = el("label");
  lockLabel.textContent = "Lock the vault after";
  const lockSelect = el("select");
  for (const minutes of AUTO_LOCK_MINUTES) {
    const option = el("option", { value: String(minutes) });
    option.textContent = `${minutes} minute${minutes === 1 ? "" : "s"} idle`;
    lockSelect.append(option);
  }
  lockSelect.value = "5";

  const status = el("p");
  status.setAttribute("role", "status");

  const pairButton = el("button");
  pairButton.textContent = "Pair";
  pairButton.addEventListener("click", async () => {
    status.textContent = "";
    let origin: string;
    try {
      origin = parseServerOrigin(serverInput.value);
    } catch (err) {
      status.textContent = (err as Error).message;
      return;
    }
    pairButton.disabled = true;
    try {
      const io = {
        requestHost: (pattern: string) => ext.permissions.request({ origins: [pattern] }),
        fetch,
      };
      const deviceName = nameInput.value.trim() || "Browser extension";
      const { deviceId, sessionToken } = await pair(io, origin, codeInput.value, deviceName);
      await saveSettings({
        serverOrigin: origin,
        sessionToken,
        deviceId,
        deviceName,
        autoLockMinutes: parseAutoLockMinutes(Number(lockSelect.value)),
      });
      await notifyBackground({ type: "paired" });
      await render();
    } catch (err) {
      status.textContent = (err as Error).message;
    } finally {
      pairButton.disabled = false;
    }
  });

  root.append(
    intro,
    serverLabel, serverInput,
    codeLabel, codeInput,
    nameLabel, nameInput,
    lockLabel, lockSelect,
    pairButton, status,
  );
}

render();
