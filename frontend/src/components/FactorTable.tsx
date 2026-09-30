import { useApp } from "../app/context";
import type { Factor } from "../lib/types";

export function FactorTable({ factors, total, caption, unit = "" }:
  { factors: Factor[]; total: number; caption: string; unit?: string }) {
  const { t, x } = useApp();
  return (
    <table className="factors">
      <caption>{caption}: <strong className="num">{total}{unit}</strong></caption>
      <thead><tr><th scope="col">{t("inc.factor")}</th><th scope="col">{t("inc.weight")}</th><th scope="col">{t("inc.contribution")}</th></tr></thead>
      <tbody>
        {factors.map((f) => (
          <tr key={f.name}>
            <th scope="row"><span className="f-name">{x(f.name)}</span><span className="muted small">{x(f.explanation)}</span></th>
            <td className="num">{Math.round(f.weight * 100)}%</td>
            <td>
              <span className="f-bar"><span style={{ inlineSize: `${Math.min(100, (f.contribution / (f.weight * 100 || 1)) * 100)}%` }} /></span>
              <span className="num">{f.contribution.toFixed(1)}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
