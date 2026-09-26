// Background side of Fill. Checks the entry against the tab, probes every frame for
// its origin and login fields (content/fill.js, no credentials), then sends the
// credentials to one same-site frame only, as fillFrame's executeScript args.
import { sameSite } from "./domain";
import type { Targets } from "./fillTargets";

// [expected origin, input count, password index, username index or -1, username, password]
export type FillArgs = [string, number, number, number, string, string];

export type FillIO = {
  tabUrl: string | undefined;
  // executeScript({files: ["content/fill.js"], allFrames: true}) results.
  probe: () => Promise<{ frameId: number; result?: unknown }[]>;
  // executeScript({func: fillFrame, args, frameIds: [frameId]}) result.
  fill: (frameId: number, args: FillArgs) => Promise<unknown>;
};

export type Login = { url: string; username: string; password: string };

type Probe = { origin: string; count: number; targets: Targets | null };

function parse(url: string): URL | undefined {
  try {
    return new URL(url);
  } catch {
    return undefined;
  }
}

const web = (u: URL | undefined): u is URL => u?.protocol === "https:" || u?.protocol === "http:";

// An https login fills only over https; an http login may fill on either.
const secureEnough = (entry: URL, page: URL) => page.protocol === "https:" || entry.protocol === "http:";

function isProbe(v: unknown): v is Probe {
  const p = v as Probe | null;
  return typeof p?.origin === "string" && Number.isSafeInteger(p.count) &&
    (p.targets === null || (typeof p.targets === "object" && Number.isSafeInteger(p.targets.password)));
}

export async function fillTab(io: FillIO, login: Login): Promise<{ username: boolean }> {
  const tab = parse(io.tabUrl ?? "");
  if (!web(tab)) throw new Error("KyVault fills only on web pages.");
  const entry = parse(login.url);
  if (!web(entry)) throw new Error("This login has no website address. Add one in the KyVault web app to fill it.");
  if (!sameSite(entry.hostname, tab.hostname)) throw new Error(`This login is for ${entry.hostname}, not ${tab.hostname}.`);
  if (!secureEnough(entry, tab)) throw new Error("This page is not secure. KyVault fills this login only over HTTPS.");

  let frames;
  try {
    frames = await io.probe();
  } catch {
    throw new Error("KyVault cannot fill on this page.");
  }
  const target = frames
    .filter((f) => f.result !== undefined && isProbe(f.result) && f.result.targets)
    .map((f) => ({ frameId: f.frameId, probe: f.result as Probe & { targets: Targets } }))
    .filter(({ probe }) => {
      const page = parse(probe.origin);
      return web(page) && sameSite(entry.hostname, page.hostname) && secureEnough(entry, page);
    })
    .sort((a, b) => a.frameId - b.frameId)[0];
  if (!target) throw new Error("No login form on this page.");

  const { origin, count, targets } = target.probe;
  const username = login.username !== "" && targets.username !== undefined;
  const filled = await io.fill(target.frameId, [origin, count, targets.password, username ? targets.username! : -1, login.username, login.password]);
  if (filled !== true) throw new Error("The page changed before filling. Try again.");
  return { username };
}

// Runs in the chosen frame's isolated world via executeScript({func, args}), so it must
// reference nothing outside itself. Refuses if the frame navigated or the form changed
// since the probe. Sets values through the native setter so React and Vue notice, fires
// bubbling input and change events, and never submits.
export function fillFrame(origin: string, count: number, password: number, username: number, user: string, pass: string): boolean {
  const inputs = document.querySelectorAll("input");
  const pw = inputs[password];
  const name = username >= 0 ? inputs[username] : undefined;
  const ok = location.origin === origin && inputs.length === count && pw?.type === "password" &&
    (username < 0 || (name !== undefined && ["text", "email"].includes(name.type)));
  if (ok) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
    // No inner named functions: bundlers may wrap those in a helper this frame lacks.
    const fields: [HTMLInputElement, string][] = name ? [[name, user], [pw, pass]] : [[pw, pass]];
    for (const [el, value] of fields) {
      el.focus();
      setter.call(el, value);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    }
    fields.length = 0;
  }
  user = pass = "";
  return ok;
}
