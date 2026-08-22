import { cp, mkdir, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const source = fileURLToPath(new URL("../dist/", import.meta.url));
const target = fileURLToPath(new URL("../../bin/web/dist/", import.meta.url));

await rm(target, { recursive: true, force: true });
await mkdir(dirname(target), { recursive: true });
await cp(source, target, { recursive: true });

console.log(`copied web console to ${target}`);
