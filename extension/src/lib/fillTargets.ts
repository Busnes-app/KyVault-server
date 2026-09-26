// Pure and import-free: the content script bundles this into its IIFE.
export type Candidate = { index: number; type: string; visible: boolean; focused: boolean; autocomplete: string };
export type Targets = { password: number; username?: number };

const USERNAME_TYPES = new Set(["text", "email", ""]);

// Password: the focused visible password field, else the first visible one. Username:
// an autocomplete=username/email field before it, else the nearest preceding text field.
export function chooseTargets(fields: Candidate[]): Targets | undefined {
  const passwords = fields.filter((f) => f.visible && f.type === "password");
  const password = passwords.find((f) => f.focused) ?? passwords[0];
  if (!password) return undefined;
  const before = fields.filter((f) => f.index < password.index && f.visible && USERNAME_TYPES.has(f.type));
  const labelled = before.find((f) => f.autocomplete === "username" || f.autocomplete === "email");
  const username = (labelled ?? before[before.length - 1])?.index;
  return { password: password.index, username };
}
