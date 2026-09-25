export function formatInterval(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "Unknown";
  if (seconds === 0) return "Off";
  const minutes = Math.round(seconds / 60);
  if (minutes % 1440 === 0) return minutes === 1440 ? "Daily" : `Every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return minutes === 60 ? "Hourly" : `Every ${minutes / 60} hours`;
  return `Every ${minutes} minutes`;
}

export function formatWhen(iso: string | undefined): string {
  if (!iso) return "Unknown";
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? "Unknown" : t.toLocaleString();
}
