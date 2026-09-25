import { checkMasterPassword } from "./masterPassword";

export function unlockMode(version: number | undefined): "create" | "unlock" {
  return version ? "unlock" : "create";
}

export function checkCreatePassword(password: string, confirm: string): string | null {
  return checkMasterPassword(password) ?? (password === confirm ? null : "The passwords do not match.");
}
