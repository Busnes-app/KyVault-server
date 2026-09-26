const BAD = () => new Error("Enter the server address as https://host, no path.");

// People paste the login page URL; tolerate a path and drop it, but refuse
// anything that is not a bare https origin (credentials in the URL, other schemes).
export function parseServerOrigin(input: string): string {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw BAD();
  }
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password) throw BAD();
  return url.origin;
}
