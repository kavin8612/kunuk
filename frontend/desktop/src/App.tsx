import { useEffect, useState } from "react";
import { isUnlocked } from "./tauri";
import { RegisterScreen } from "./screens/RegisterScreen";
import { LoginScreen } from "./screens/LoginScreen";
import { SecretKeyRevealScreen } from "./screens/SecretKeyRevealScreen";
import { VaultScreen } from "./screens/VaultScreen";
import "./app.css";

type Screen =
  | { name: "loading" }
  | { name: "register" }
  | { name: "login" }
  | { name: "reveal-secret-key"; secretKey: string }
  | { name: "vault" };

export function App() {
  const [screen, setScreen] = useState<Screen>({ name: "loading" });

  useEffect(() => {
    isUnlocked()
      .then((unlocked) => {
        setScreen(unlocked ? { name: "vault" } : { name: "register" });
      })
      .catch(() => {
        setScreen({ name: "register" });
      });
  }, []);

  switch (screen.name) {
    case "loading":
      return null;
    case "register":
      return (
        <RegisterScreen
          onRegistered={(secretKey) => {
            setScreen({ name: "reveal-secret-key", secretKey });
          }}
          onSwitchToLogin={() => {
            setScreen({ name: "login" });
          }}
        />
      );
    case "login":
      return (
        <LoginScreen
          onUnlocked={() => {
            setScreen({ name: "vault" });
          }}
          onSwitchToRegister={() => {
            setScreen({ name: "register" });
          }}
        />
      );
    case "reveal-secret-key":
      return (
        <SecretKeyRevealScreen
          secretKey={screen.secretKey}
          onContinue={() => {
            setScreen({ name: "vault" });
          }}
        />
      );
    case "vault":
      return (
        <VaultScreen
          onLocked={() => {
            setScreen({ name: "login" });
          }}
        />
      );
  }
}
