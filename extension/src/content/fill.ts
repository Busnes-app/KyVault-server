// Injected into every frame of the active tab by scripting.executeScript({files}) when
// the user clicks Fill; never registered in the manifest. It reads field metadata only,
// never values, and holds no credentials: those go to one chosen frame through
// fillFrame's executeScript args. The completion value (the outro in
// vite.content.config.ts) is the probe result; nothing is declared outside the IIFE.
import { chooseTargets, type Candidate } from "../lib/fillTargets";

function probe() {
  const inputs = Array.from(document.querySelectorAll("input"));
  const fields: Candidate[] = inputs.map((el, index) => ({
    index,
    type: el.type.toLowerCase(),
    visible: el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden",
    focused: document.activeElement === el,
    autocomplete: el.autocomplete.trim().toLowerCase().split(/\s+/).pop() ?? "",
  }));
  return { origin: location.origin, count: inputs.length, targets: chooseTargets(fields) ?? null };
}
