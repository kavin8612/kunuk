import type { ReactNode } from "react";
import { useT } from "@kunuk/shared-ui";
import { lock } from "../tauri";
import { useAutoLock } from "../hooks/useAutoLock";

interface Props {
  autoLockMinutes: number;
  onLocked: () => void;
  children: ReactNode;
}

/** Guscio del vault sbloccato (doc 17 §9): tiene attivo l'auto-lock qualunque sia la
 * sotto-schermata mostrata da `VaultScreen` (lista, editor, generatore, impostazioni — i
 * loro `return` non passano più da qui sopra), e rende il blocco manuale raggiungibile
 * sempre dalla stessa barra, non solo dalla lista voci. */
export function AppShell(props: Props) {
  const t = useT();

  async function handleLock() {
    try {
      await lock();
    } finally {
      props.onLocked();
    }
  }

  useAutoLock({
    autoLockMinutes: props.autoLockMinutes,
    onLock: () => {
      void handleLock();
    },
  });

  return (
    <div className="app-shell">
      <div className="app-shell__bar">
        <button type="button" className="app-shell__lock" onClick={() => void handleLock()}>
          {t("vault.lock")}
        </button>
      </div>
      {props.children}
    </div>
  );
}
