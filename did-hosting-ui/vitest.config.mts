import { defineConfig } from "vitest/config";

// The lib tests run in Node. Component and screen tests opt into a DOM with
// `// @vitest-environment jsdom` and render through react-native-web, exactly
// as the exported web console does — hence the `react-native` alias.
export default defineConfig({
  resolve: {
    alias: [{ find: /^react-native$/, replacement: "react-native-web" }],
  },
  define: {
    __DEV__: "false",
  },
  test: {
    include: ["**/__tests__/**/*.test.{ts,tsx}"],
    exclude: ["node_modules/**", "dist/**"],
    server: {
      deps: {
        // Expo packages ship untranspiled ESM/JSX; let Vite transform them.
        inline: [/expo-/, /@expo\//, /react-native-web/],
      },
    },
  },
});
