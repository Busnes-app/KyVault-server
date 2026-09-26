import type { AutoLockMinutes } from "../../../frontend/src/lib/autoLock";

const SLACK_MS = 60_000;

export function lockDeadline(now: number, minutes: AutoLockMinutes): number {
  return now + minutes * 60_000;
}

// A deadline further ahead than the window allows means the clock went backwards; lock
// rather than grant the extra time. Without `minutes`, the largest window (60) bounds it.
export function isLocked(lockAt: number | undefined, now: number, minutes: AutoLockMinutes = 60): boolean {
  return lockAt === undefined || lockAt <= now || lockAt - now > minutes * 60_000 + SLACK_MS;
}
