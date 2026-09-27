// Fails the build if zxcvbn dictionaries or the 2FA list land in chunks loaded on first paint.
import { readFileSync, readdirSync } from "node:fs";

const dist = new URL("../dist/", import.meta.url);
const html = readFileSync(new URL("index.html", dist), "utf8");
const eager = [...html.matchAll(/(?:src|href)="\/(assets\/[^"]+\.js)"/g)].map((m) => m[1]);
if (eager.length === 0) throw new Error("check-bundle: no scripts found in dist/index.html");
// Strings only the lazy chunks contain: an en translation from zxcvbn, a 2FA list domain,
// and X-Wing's own algorithm name (@hpke/hybridkem-x-wing), which loads only when a user
// key is first needed (generation, unlock adoption, rotation).
const markers = ["similar to a commonly used password", "101domain.com", "X-Wing"];
for (const file of eager) {
  const js = readFileSync(new URL(file, dist), "utf8");
  for (const m of markers) if (js.includes(m)) throw new Error(`check-bundle: ${m} is in eagerly loaded ${file}`);
}
const lazy = readdirSync(new URL("assets/", dist)).filter((f) => f.endsWith(".js") && !eager.includes(`assets/${f}`));
for (const m of markers) {
  if (!lazy.some((f) => readFileSync(new URL(`assets/${f}`, dist), "utf8").includes(m))) {
    throw new Error(`check-bundle: ${m} not found in any lazy chunk; the check is no longer testing anything`);
  }
}
console.log(`check-bundle: ${eager.length} eager, ${lazy.length} lazy chunks; zxcvbn and 2FA list are lazy`);
