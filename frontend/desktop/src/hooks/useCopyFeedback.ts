import { useEffect, useRef, useState } from "react";
import { copyWithAutoClear } from "@kunuk/shared-ui";
import { getSettings } from "../tauri";

const COPIED_LABEL_MS = 2_000;

/** Copia un segreto con pulizia automatica della clipboard (doc 17 §9) e un'etichetta
 * "Copiato"/"Copied" che si auto-ripristina dopo `COPIED_LABEL_MS` — stesso comportamento
 * ovunque si copi un segreto (password Login, codice Carta, valore del Generatore, campo
 * personalizzato nascosto), invece di quattro implementazioni indipendenti e incoerenti tra
 * loro (scoperto in code review).
 *
 * `key` identifica il bottone che ha appena copiato (serve quando più "Copia" condividono lo
 * stesso componente, es. i campi personalizzati): usare una chiave costante per un singolo
 * bottone, l'indice/id del campo per una lista. `clear()` annulla subito l'etichetta — usarlo
 * quando l'elenco sottostante cambia forma (es. un campo viene rimosso) per non lasciare
 * l'etichetta "Copiato" su un campo diverso da quello effettivamente copiato. */
export function useCopyFeedback<K>(): {
  copiedKey: K | null;
  copy: (key: K, value: string) => void;
  clear: () => void;
} {
  const [copiedKey, setCopiedKey] = useState<K | null>(null);
  const timeoutRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timeoutRef.current !== null) window.clearTimeout(timeoutRef.current);
    };
  }, []);

  function clear() {
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    setCopiedKey(null);
  }

  function copy(key: K, value: string) {
    getSettings()
      .then((settings) => copyWithAutoClear(value, settings.clipboard_clear_seconds * 1000))
      .then(() => {
        setCopiedKey(key);
        if (timeoutRef.current !== null) window.clearTimeout(timeoutRef.current);
        timeoutRef.current = window.setTimeout(() => {
          setCopiedKey((current) => (current === key ? null : current));
        }, COPIED_LABEL_MS);
      })
      .catch(() => {
        /* clipboard non disponibile: nessuna azione, il valore resta visibile e selezionabile */
      });
  }

  return { copiedKey, copy, clear };
}
