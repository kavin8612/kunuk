import { useEffect, useRef } from "react";

const ACTIVITY_EVENTS: (keyof WindowEventMap)[] = [
  "mousemove",
  "mousedown",
  "keydown",
  "scroll",
  "touchstart",
];

const IDLE_CHECK_INTERVAL_MS = 5_000;

interface Options {
  autoLockMinutes: number;
  onLock: () => void;
}

/** Auto-lock (doc 17 §9): blocca dopo `autoLockMinutes` di inattività, oppure subito quando
 * la finestra passa in background. Tauri non offre un hook nativo cross-platform per gli
 * eventi di power management (sospensione/screensaver) senza codice per-OS: `visibilitychange`
 * è l'euristica scelta in sua vece (GO del titolare, 2026-06-23) — su Chromium/WebView2
 * `document.hidden` diventa vero su minimizzazione, schermo bloccato dall'OS e sospensione;
 * blocca anche se l'utente si limita a minimizzare la finestra, accettato come comportamento
 * ragionevole per un password manager. */
export function useAutoLock(options: Options): void {
  // `Date.now()`/scrittura su ref solo dentro effect: leggerli durante il render violerebbe
  // le regole di purità di React (react-hooks/purity, react-hooks/refs).
  const lastActivityRef = useRef<number | null>(null);
  const onLockRef = useRef(options.onLock);

  useEffect(() => {
    onLockRef.current = options.onLock;
  }, [options.onLock]);

  useEffect(() => {
    function markActive() {
      lastActivityRef.current = Date.now();
    }
    markActive();
    ACTIVITY_EVENTS.forEach((event) => {
      window.addEventListener(event, markActive, { passive: true });
    });
    return () => {
      ACTIVITY_EVENTS.forEach((event) => {
        window.removeEventListener(event, markActive);
      });
    };
  }, []);

  useEffect(() => {
    const timeoutMs = options.autoLockMinutes * 60_000;
    const interval = window.setInterval(() => {
      const lastActivity = lastActivityRef.current;
      if (lastActivity !== null && Date.now() - lastActivity >= timeoutMs) {
        onLockRef.current();
      }
    }, IDLE_CHECK_INTERVAL_MS);
    return () => {
      window.clearInterval(interval);
    };
  }, [options.autoLockMinutes]);

  useEffect(() => {
    function handleVisibilityChange() {
      if (document.hidden) {
        onLockRef.current();
      }
    }
    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, []);
}
