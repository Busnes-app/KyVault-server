// Request/response shapes the popup and options page send to the background
// worker, which is the single owner of the session and the open vault. No response
// ever carries the vault key.
import type { EntryView } from "./lib/rank";
import type { NewLogin, SecretField } from "./lib/vaultState";

export type Request =
  | { type: "paired" }
  | { type: "unpair" }
  | { type: "status" }
  | { type: "unlock"; password: string }
  | { type: "ensure" }
  | { type: "lock" }
  | { type: "entries"; query: string }
  | { type: "copy"; uuid: string; field: SecretField }
  | { type: "fill"; uuid: string }
  | { type: "saveLogin"; login: NewLogin }
  | { type: "copied" };

export type StatusResponse = {
  paired: boolean;
  unlocked: boolean;
  serverOrigin?: string;
  deviceName?: string;
  lockAt?: number;
};

export type Response =
  | { type: "status"; status: StatusResponse }
  | { type: "ok" }
  // tabOrigin is set only for http(s) tabs; it prefills the save form.
  | { type: "entries"; tabHost?: string; tabOrigin?: string; entries: EntryView[] }
  | { type: "secret"; value: string }
  | { type: "filled"; username: boolean }
  // revoked: the popup also offers the options page link.
  | { type: "error"; message: string; revoked?: boolean; locked?: boolean };
