import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
      },
    },
    rules: {
      // Obbligatori da doc 19 §8: niente any, niente promise senza gestione
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-floating-promises": "error",
      // Stringhe utente mai hardcoded: ricordare di usare i cataloghi i18n
      "no-restricted-syntax": [
        "warn",
        {
          selector: "Literal[value=/^[A-Z]/]",
          message: "Le stringhe rivolte all'utente vanno nei cataloghi i18n (doc 19 §1).",
        },
      ],
    },
  },
  {
    files: ["desktop/src/**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks, "react-refresh": reactRefresh },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": "warn",
    },
  },
  {
    // I cataloghi sono la fonte: ovvio che contengano stringhe capitalizzate, non una
    // violazione della regola. I *.config.ts (es. vite.config.ts) non hanno testo utente.
    files: ["**/i18n/it.ts", "**/i18n/en.ts", "**/*.config.ts"],
    rules: {
      "no-restricted-syntax": "off",
    },
  },
  {
    // src-tauri/target: output di build di cargo (Rust), non sorgente TS — un .js generato
    // lì dentro confonderebbe il project service di eslint. src-tauri/gen: schemi generati
    // da Tauri (già in .gitignore alla radice).
    ignores: [
      "dist/",
      "node_modules/",
      "*.config.mjs",
      "**/src-tauri/target/**",
      "**/src-tauri/gen/**",
    ],
  }
);
