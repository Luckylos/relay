import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: "./wrangler.toml",
      },
      // EGRESS_RELAY_SECRET and INGRESS_AUTH_TOKEN are Worker secrets, so they
      // are absent from wrangler.toml by design. Tests supply throwaway values.
      miniflare: {
        bindings: {
          EGRESS_RELAY_SECRET: "integration-test-secret",
          INGRESS_AUTH_TOKEN: "aW50ZWdyYXRpb24tdGVzdC1pbmdyZXNzLXRva2VuLTAwMDAw",
        },
      },
    }),
  ],
  test: {
    globals: true,
  },
});
