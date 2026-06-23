import { useT } from "@kunuk/shared-ui";

interface Props {
  secretKey: string;
  onContinue: () => void;
}

/** Esposizione one-shot della Secret Key appena generata (EmergencyKit): l'utente deve
 * copiarla e conservarla offline prima di proseguire. Il core non la ripeterà più. */
export function SecretKeyRevealScreen(props: Props) {
  const t = useT();
  return (
    <div className="auth-form">
      <h1 className="auth-form__title">{t("auth.register.success")}</h1>
      <code className="secret-key-reveal">{props.secretKey}</code>
      <button type="button" className="auth-form__primary" onClick={props.onContinue}>
        {t("auth.register.continue")}
      </button>
    </div>
  );
}
