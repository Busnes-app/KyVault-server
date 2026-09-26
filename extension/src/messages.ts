// Request/response shapes the popup and options page send to the background
// worker, which is the single owner of the session and the open vault. No response
// ever carries the vault key.
export type Request =
  | { type: "paired" }
  | { type: "unpair" }
  | { type: "status" }
  | { type: "unlock"; password: string }
  | { type: "ensure" }
  | { type: "lock" };

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
  // revoked: the popup also offers the options page link.
  | { type: "error"; message: string; revoked?: boolean; locked?: boolean };
