import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts", // MCP server (bin)
    engine: "src/engine.ts", // reusable engine (library export)
  },
  format: ["esm"],
  target: "node20",
  dts: true,
  clean: true,
  sourcemap: true,
  shims: false,
});
