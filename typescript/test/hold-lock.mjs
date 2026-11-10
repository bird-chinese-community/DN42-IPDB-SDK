import { lock } from "proper-lockfile";

const release = await lock(process.argv[2], {
  retries: 0,
  lockfilePath: `${process.argv[2]}/.update.lock`,
});
process.send("locked");
process.once("message", async () => {
  await release();
  process.exit(0);
});
