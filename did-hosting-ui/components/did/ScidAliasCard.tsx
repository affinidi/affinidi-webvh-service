import type { ReactNode } from "react";
import { Text, View } from "react-native";

import type { ScidAliasAction, ScidAliasState, ScidAliasView } from "../../lib/scid-alias";
import { colors, spacing } from "../../lib/theme";
import { Button } from "../Button";
import { Card } from "../Card";
import { didStyles } from "./styles";

/** The did:scid form of this log, and whether the document lists it. */
export function ScidAliasCard({
  alias,
  panel,
  publishing,
  onAction,
  consentPanel,
}: {
  alias: ScidAliasState;
  panel: ScidAliasView;
  publishing: boolean;
  onAction: (action: ScidAliasAction) => void;
  /** The approval code, while a change this card asked for waits on the user. */
  consentPanel: ReactNode;
}) {
  const statusColor =
    alias.status === "listed"
      ? colors.success
      : alias.status === "stale"
        ? colors.warning
        : colors.textSecondary;
  return (
    <Card title="did:scid Alias" style={didStyles.card}>
      <Text style={didStyles.hint}>
        This log also verifies {alias.didUrl}. The two forms are one subject only while the document
        lists it in alsoKnownAs.
      </Text>
      <Text style={{ marginTop: spacing.md, color: statusColor }}>{panel.summary}</Text>
      {panel.readOnlyReason ? (
        <Text style={[didStyles.hint, { marginTop: spacing.md }]}>{panel.readOnlyReason}</Text>
      ) : (
        <View style={didStyles.stack}>
          {panel.warning && <Text style={didStyles.hint}>{panel.warning}</Text>}
          <View style={didStyles.row}>
            {panel.actions.map((action) => (
              <Button
                key={action.label}
                size="sm"
                variant="secondary"
                label={action.label}
                busy={publishing}
                busyLabel="Asking your agent..."
                onPress={() => onAction(action)}
              />
            ))}
          </View>
          {consentPanel}
        </View>
      )}
    </Card>
  );
}
