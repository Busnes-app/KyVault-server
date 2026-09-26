// Sequences modal questions so a second ask waits for the first answer instead of
// replacing it. Pure so it can be tested without React.
export type DialogRequest = {
  kind: "confirm" | "prompt" | "notify" | "choose";
  title: string;
  message?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  label?: string;
  defaultValue?: string;
  validate?: (value: string) => string | null;
  options?: Array<{ value: string; label: string }>;
};

type Pending = { id: number; request: DialogRequest; resolve: (value: unknown) => void };

export class DialogQueue {
  private pending: Pending[] = [];
  private listeners = new Set<() => void>();
  private seq = 0;

  ask<T>(request: DialogRequest): Promise<T> {
    return new Promise<T>((resolve) => {
      this.pending.push({ id: ++this.seq, request, resolve: resolve as (value: unknown) => void });
      if (this.pending.length === 1) this.notify();
    });
  }

  current(): DialogRequest | null { return this.pending[0]?.request ?? null; }
  // Distinct per question so two identical consecutive questions do not share form state.
  currentId(): number { return this.pending[0]?.id ?? 0; }

  settle(value: unknown): void {
    const head = this.pending.shift();
    if (!head) return;
    head.resolve(value);
    this.notify();
  }

  // Answers every open question with its kind's cancel value and clears the queue,
  // so a handler suspended mid-question cannot be resumed later.
  cancelAll(): void {
    const rest = this.pending;
    this.pending = [];
    for (const item of rest) {
      const cancelValue = item.request.kind === "confirm" ? false :
        item.request.kind === "prompt" || item.request.kind === "choose" ? null : undefined;
      item.resolve(cancelValue);
    }
    if (rest.length) this.notify();
  }

  // Arrow property so React can hold a stable reference for useSyncExternalStore.
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  private notify() { this.listeners.forEach((l) => l()); }
}
