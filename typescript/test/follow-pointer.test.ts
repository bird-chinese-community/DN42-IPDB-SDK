import assert from "node:assert/strict";
import { test } from "node:test";
import { followPointer, maxOpenAttempts } from "../src/follow-pointer.ts";

const stale = new Error("stale");
const isStale = (error: unknown) => error === stale;

await test("opens the new target when the pointer moved during a read", async () => {
  const versions = ["a", "b"];
  const opened: string[] = [];
  const result = await followPointer(
    async () => ({ version: versions.shift() ?? "b" }),
    async (pointer) => {
      opened.push(pointer.version);
      if (pointer.version === "a") throw stale;
      return pointer.version;
    },
    isStale,
  );
  assert.equal(result, "b");
  assert.deepEqual(opened, ["a", "b"]);
});

await test("surfaces the error when the pointer did not move", async () => {
  let reads = 0;
  await assert.rejects(
    followPointer(
      async () => {
        reads++;
        return { version: "a" };
      },
      async () => {
        throw stale;
      },
      isStale,
    ),
    stale,
  );
  assert.equal(reads, 2);
});

await test("stops after the last attempt", async () => {
  let version = 0;
  let opens = 0;
  await assert.rejects(
    followPointer(
      async () => ({ version: String(version++) }),
      async () => {
        opens++;
        throw stale;
      },
      isStale,
    ),
    stale,
  );
  assert.equal(opens, maxOpenAttempts);
});

await test("does not retry other errors", async () => {
  const other = new Error("other");
  let opens = 0;
  await assert.rejects(
    followPointer(
      async () => ({ version: "a" }),
      async () => {
        opens++;
        throw other;
      },
      isStale,
    ),
    other,
  );
  assert.equal(opens, 1);
});
