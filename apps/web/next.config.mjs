/** @type {import('next').NextConfig} */
const nextConfig = {
  // Workspace packages ship TypeScript sources directly (main -> ./src/index.ts)
  // and are symlinked into node_modules. Next/Turbopack does not compile
  // node_modules by default, so opt these packages in explicitly.
  transpilePackages: ["@kleidion/crypto", "@kleidion/core"],
};

export default nextConfig;
