// Request/response shapes the popup and options page send to the background
// worker, which is the single owner of the session and the open vault.
export type Request =
  | { type: "paired" }
  | { type: "unpair" }
  | { type: "status" };

export type StatusResponse = {
  paired: boolean;
  unlocked: boolean;
  serverOrigin?: string;
  deviceName?: string;
  lockAt?: number;
};

export type Response = { type: "status"; status: StatusResponse } | { type: "ok" };
