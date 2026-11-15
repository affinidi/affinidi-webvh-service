import { useEffect, useState } from "react";
import { Text, type StyleProp, type TextStyle } from "react-native";

import { formatDuration, nowSecs } from "../lib/time";

/** Time left until `expiresAt`, compact ("1h 5m"), or "expiring" once due. */
export function remainingLabel(expiresAt: number, now: number): string {
  const left = expiresAt - now;
  if (left <= 0) return "expiring";
  return formatDuration(left, { style: "compact", maxParts: 2 });
}

/**
 * A live countdown to `expiresAt` (epoch seconds).
 *
 * It ticks every second on its own, so only this text re-renders — not the
 * page around it, and nothing at all on a page that shows no countdown.
 */
export function Countdown({
  expiresAt,
  style,
}: {
  expiresAt: number;
  style?: StyleProp<TextStyle>;
}) {
  const [now, setNow] = useState(nowSecs);
  useEffect(() => {
    const t = setInterval(() => setNow(nowSecs()), 1000);
    return () => clearInterval(t);
  }, []);
  return <Text style={style}>{remainingLabel(expiresAt, now)}</Text>;
}
