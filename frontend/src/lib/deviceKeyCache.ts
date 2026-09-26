// Caching the device key races "Forget This Device" and auto-lock: both clear the
// cache and bump the unlock generation, but a store that was already in flight lands
// afterwards and quietly restores the key. Every cache write therefore re-checks the
// generation after the write and undoes itself when it lost the race.
export async function cacheDeviceKey(io: {
  store: () => Promise<void>;
  clear: () => Promise<void>;
  stillCurrent: () => boolean;
}): Promise<"cached" | "discarded" | "failed"> {
  if (!io.stillCurrent()) return "discarded";
  try {
    await io.store();
  } catch {
    return "failed";
  }
  if (io.stillCurrent()) return "cached";
  await io.clear().catch(() => {});
  return "discarded";
}
