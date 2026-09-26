import { cp, mkdir, readFile, writeFile } from "node:fs/promises";

await mkdir("dist", { recursive: true });
await cp("src/styles.css", "dist/styles.css");
await cp("public", "dist", { recursive: true });
const html = await readFile("index.html", "utf8");
const productionHtml = html.replace('/src/main.ts', '/main.js');
await writeFile("dist/index.html", productionHtml);
