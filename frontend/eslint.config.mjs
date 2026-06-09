import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

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
    ignores: ["dist/", "node_modules/", "*.config.mjs"],
  }
);
