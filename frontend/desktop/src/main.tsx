import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { I18nProvider, detectLocale } from "@kunuk/shared-ui";
// Import via JS (non <link> in index.html): Vite risolve i percorsi relativi fuori dalla
// root del progetto solo attraverso il grafo dei moduli, non per gli asset statici servuti
// direttamente dal dev server (doc 06: i token vivono in frontend/shared-ui/tokens/).
import "../../shared-ui/tokens/colors.css";
import "../../shared-ui/tokens/typography.css";
import { App } from "./App";

const locale = detectLocale(navigator.language);

// eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- index.html lo definisce sempre
const root = document.getElementById("root")!;

createRoot(root).render(
  <StrictMode>
    <I18nProvider locale={locale}>
      <App />
    </I18nProvider>
  </StrictMode>
);
