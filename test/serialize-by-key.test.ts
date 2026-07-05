import { describe, expect, test } from "bun:test";

import { serializeByKey } from "../src/validation.js";

describe("serializeByKey", () => {
  test("same-key operations run sequentially (never overlap)", async () => {
    const chains = new Map<string, Promise<unknown>>();
    const order: string[] = [];
    const op = (id: string) => async () => {
      order.push(`${id}:start`);
      await Promise.resolve();
      order.push(`${id}:end`);
    };
    const p1 = serializeByKey(chains, "k", op("a"));
    const p2 = serializeByKey(chains, "k", op("b"));
    await Promise.all([p1, p2]);
    // b only starts after a has fully finished.
    expect(order).toEqual(["a:start", "a:end", "b:start", "b:end"]);
  });

  test("a rejecting op does not break the chain for the next same-key op", async () => {
    const chains = new Map<string, Promise<unknown>>();
    const order: string[] = [];
    const p1 = serializeByKey(chains, "k", async () => {
      order.push("a");
      throw new Error("boom");
    });
    const p2 = serializeByKey(chains, "k", async () => {
      order.push("b");
    });
    await expect(p1).rejects.toThrow("boom");
    await p2; // still runs
    expect(order).toEqual(["a", "b"]);
  });

  test("different keys are NOT serialized against each other", async () => {
    const chains = new Map<string, Promise<unknown>>();
    let bRan = false;
    const p1 = serializeByKey(chains, "A", async () => {
      // B (a different key) should get to run while A is still pending.
      await Promise.resolve();
      expect(bRan).toBe(true);
    });
    const p2 = serializeByKey(chains, "B", async () => {
      bRan = true;
    });
    await Promise.all([p1, p2]);
  });

  test("returns the op's resolved value", async () => {
    const chains = new Map<string, Promise<unknown>>();
    await expect(serializeByKey(chains, "k", async () => 42)).resolves.toBe(42);
  });
});
