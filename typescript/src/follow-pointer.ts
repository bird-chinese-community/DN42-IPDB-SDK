/** At most this many reads of a pointed release while writers move the pointer. */
export const maxOpenAttempts = 3;

/**
 * Opens the release a pointer names. When the read fails with a stale-read error
 * and the pointer has moved since, it opens the new target instead.
 */
export async function followPointer<Pointer extends { version: string }, Result>(
  readPointer: () => Promise<Pointer>,
  openPointed: (pointer: Pointer) => Promise<Result>,
  isStaleRead: (error: unknown) => boolean,
): Promise<Result> {
  let pointer = await readPointer();
  for (let attempt = 1; ; attempt++) {
    try {
      return await openPointed(pointer);
    } catch (error) {
      if (attempt === maxOpenAttempts || !isStaleRead(error)) throw error;
      const next = await readPointer();
      if (next.version === pointer.version) throw error;
      pointer = next;
    }
  }
}
