import { useT } from "@kunuk/shared-ui";
import { strengthFromEntropyBits, type Strength } from "@kunuk/shared-ui";

interface Props {
  bits: number;
}

const WIDTH: Record<Strength, string> = {
  weak: "25%",
  fair: "50%",
  good: "75%",
  strong: "100%",
};

const LABEL_KEY: Record<
  Strength,
  "strength.weak" | "strength.fair" | "strength.good" | "strength.strong"
> = {
  weak: "strength.weak",
  fair: "strength.fair",
  good: "strength.good",
  strong: "strength.strong",
};

/** Indicatore di robustezza condiviso tra registrazione e generatore (doc 17 §3): solo
 * larghezza/peso, niente colore semantico nuovo (Brand Book, design/palette/palette.md). */
export function StrengthMeter(props: Props) {
  const t = useT();
  const strength = strengthFromEntropyBits(props.bits);
  return (
    <div className="strength-meter">
      <div className="strength-meter__track">
        <div
          className={`strength-meter__fill strength-meter__fill--${strength}`}
          style={{ width: WIDTH[strength] }}
        />
      </div>
      <span className="strength-meter__label">{t(LABEL_KEY[strength])}</span>
    </div>
  );
}
