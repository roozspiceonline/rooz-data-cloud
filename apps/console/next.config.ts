import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  transpilePackages: ["@rdc/api-client", "@rdc/shared-types", "@rdc/ui"],
};

export default nextConfig;
