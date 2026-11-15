import { useState } from "react";
import { Text } from "react-native";

import type { Response as SetResolutionResponse } from "../../lib/trust-tasks/did-management/stats/set-resolution/0.1/payload";
import { errorMessage } from "../../lib/errors";
import { notify } from "../../lib/feedback";
import { useApi } from "../ApiProvider";
import { Card } from "../Card";
import { SegmentedControl, type SegmentOption } from "../SegmentedControl";
import { didStyles } from "./styles";

type Resolution = SetResolutionResponse["resolution"];

const DESCRIPTIONS: Record<Resolution, string> = {
  auto: "The service decides from the DID's traffic.",
  fine: "Always keep 5-minute detail.",
  coarse: "Keep hourly and daily detail only.",
  off: "Keep the totals only, with no history over time.",
};

const TIER_LABEL: Record<SetResolutionResponse["tier"], string> = {
  fine: "5-minute detail",
  coarse: "hourly and daily detail",
  off: "totals only",
};

const REASON_LABEL: Record<SetResolutionResponse["tierReason"], string> = {
  override: "set here",
  policy: "a service-wide setting applies to every DID",
  traffic: "chosen from this DID's traffic",
};

/**
 * How much usage history the service keeps for this DID
 * (`stats/set-resolution`). The control plane has no read for the current
 * setting, so the picker starts unselected and shows what was set — and what
 * the service actually keeps, and why — once the operator chooses.
 */
export function StatsResolutionCard({
  mnemonic,
  isAdmin,
}: {
  mnemonic: string;
  /** 5-minute detail is an administrator's call. */
  isAdmin: boolean;
}) {
  const api = useApi();
  const [result, setResult] = useState<SetResolutionResponse | null>(null);
  const [busy, setBusy] = useState(false);

  const options: SegmentOption<Resolution>[] = [
    { value: "auto", label: "Automatic" },
    { value: "fine", label: "5-minute", disabled: !isAdmin },
    { value: "coarse", label: "Hourly" },
    { value: "off", label: "Totals only" },
  ];

  const choose = async (resolution: Resolution) => {
    if (busy) return;
    setBusy(true);
    try {
      const r = await api.setStatsResolution(mnemonic, resolution);
      setResult(r);
      notify(
        "success",
        "Statistics detail saved",
        `Now keeping ${TIER_LABEL[r.tier]} (${REASON_LABEL[r.tierReason]}).`,
      );
    } catch (e: unknown) {
      notify("error", "Could not change the statistics detail", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Statistics detail" style={didStyles.card}>
      <Text style={didStyles.hint}>
        How much usage history the service keeps for this DID. Finer detail costs storage.
        {isAdmin ? "" : " 5-minute detail can be set by an administrator."}
      </Text>
      <SegmentedControl
        label="Statistics detail"
        options={options}
        value={result?.resolution ?? null}
        onChange={(v) => void choose(v)}
      />
      <Text style={didStyles.hint} aria-live="polite">
        {result
          ? `${DESCRIPTIONS[result.resolution]} The service keeps ${TIER_LABEL[result.tier]} — ${REASON_LABEL[result.tierReason]}.`
          : "The current setting is shown once you choose one."}
      </Text>
    </Card>
  );
}
