import tailwindcss from "@tailwindcss/vite";
import { devtools } from "@tanstack/devtools-vite";

import { tanstackStart } from "@tanstack/react-start/plugin/vite";

import viteReact from "@vitejs/plugin-react";
import { nitro } from "nitro/vite";
import { defineConfig } from "vite";

const reactExternals = [
  "react",
  "react-dom",
  "react-dom/server",
  "react-dom/server.node",
  "react/jsx-runtime",
  "react/jsx-dev-runtime",
];

const config = defineConfig({
  resolve: { tsconfigPaths: true },
  plugins: [
    devtools(),
    nitro({
      preset: "bun",
      rollupConfig: {
        external: [/^@sentry\//, ...reactExternals],
        output: {
          paths: {
            "react-dom/server": "react-dom/server.node",
          },
        },
      },
    }),
    tailwindcss(),
    tanstackStart(),
    viteReact(),
  ],
});

export default config;
