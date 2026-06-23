// Copia con pulizia automatica (doc 17 §9): quando si copia un segreto, la clipboard si
// svuota da sola dopo un tempo configurabile, non resta lì indefinitamente.

/** Timer di pulizia in sospeso: una nuova copia annulla quello della copia precedente, così
 * la pulizia segue sempre l'ultima copia (non la prima) — altrimenti copiare due volte lo
 * stesso segreto farebbe scadere la clipboard al timeout della prima copia, troncando la
 * finestra di protezione della seconda (scoperto in code review). */
let pendingClear: { timeoutId: ReturnType<typeof setTimeout> } | null = null;

/** Copia `value` negli appunti e programma la pulizia dopo `delayMs`. Verifica best-effort
 * (`readText`) che la clipboard contenga ancora lo stesso valore prima di svuotarla; se la
 * verifica non è possibile (permesso negato, finestra senza focus) la svuota comunque:
 * fail-closed, un segreto rimasto in chiaro pesa più del raro falso positivo che sovrascrive
 * una copia successiva dell'utente. */
export function copyWithAutoClear(value: string, delayMs: number): Promise<void> {
  return navigator.clipboard.writeText(value).then(() => {
    if (pendingClear !== null) {
      clearTimeout(pendingClear.timeoutId);
    }
    const timeoutId = setTimeout(() => {
      pendingClear = null;
      void clearIfUnchanged(value);
    }, delayMs);
    pendingClear = { timeoutId };
  });
}

async function clearIfUnchanged(value: string): Promise<void> {
  try {
    const current = await navigator.clipboard.readText();
    if (current !== value) return;
  } catch {
    // Verifica non disponibile: si svuota comunque (fail-closed, vedi sopra).
  }
  try {
    await navigator.clipboard.writeText("");
  } catch (err) {
    // Pulizia fallita (permesso revocato, clipboard occupata da un altro processo): nessun
    // retry (il timer è già scaduto), ma un avviso a console per non sparire nel nulla —
    // il segreto resta in chiaro negli appunti oltre il timeout configurato.
    console.warn("copyWithAutoClear: pulizia della clipboard fallita", err);
  }
}
