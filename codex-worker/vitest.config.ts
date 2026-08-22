import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.toml",
      },
      // EGRESS_RELAY_SECRET is a Worker secret, so it is absent from
      // wrangler.toml by design. Tests supply a throwaway value.
      miniflare: {
        bindings: {
          EGRESS_RELAY_SECRET: "integration-test-secret",
        },
      },
    }),
  ],
  test: {
    globals: true,
  },
});
