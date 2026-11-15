import { useEffect, useRef, useState, type ReactNode } from "react";
import { StyleSheet, Text, View } from "react-native";

import type { AgentNameEntry } from "../../lib/api";
import { colors, fonts, spacing } from "../../lib/theme";
import { useApi } from "../ApiProvider";
import { Button } from "../Button";
import { Card } from "../Card";
import { Field } from "../Field";
import { agentNameLabel } from "./agent-names";
import { didStyles } from "./styles";

type NameStatus = "checking" | "available" | "taken" | "reserved" | "error" | null;

const STATUS_TEXT: Record<Exclude<NameStatus, null>, string> = {
  checking: "Checking…",
  available: "Available",
  taken: "Already taken on this domain",
  reserved: "Reserved by the host",
  error: "Could not check availability",
};

/**
 * Agent names — `domain/@alice` shortcuts that redirect to this DID.
 *
 * A name is served because the signed document claims it via `alsoKnownAs`,
 * so binding or removing one publishes a new version through the agent.
 * Parking keeps a name reserved to this DID while it is not served.
 */
export function AgentNamesCard({
  mnemonic,
  agentDomain,
  hasDidId,
  registry,
  boundNames,
  parkedNames,
  canBindCommunityName,
  canDelegate,
  publishing,
  onBind,
  onBindCommunityName,
  onPark,
  onUnbind,
  onResume,
  consentPanel,
}: {
  mnemonic: string;
  agentDomain: string | null;
  hasDidId: boolean;
  /** The host's registry for this DID (served + parked); `null` until the
   *  record has loaded. */
  registry: AgentNameEntry[] | null;
  /** Names the live document claims. */
  boundNames: string[];
  /** Names reserved to this DID but not served. */
  parkedNames: string[];
  canBindCommunityName: boolean;
  /** A connected wallet can relay the publish. */
  canDelegate: boolean;
  publishing: boolean;
  /** Start publishing a version that also claims `name`. `false` when it was
   *  refused before anything was sent (already bound). */
  onBind: (name: string) => boolean;
  onBindCommunityName: () => void;
  onPark: (name: string) => void;
  onUnbind: (name: string) => void;
  onResume: (name: string) => void;
  /** The approval code, while a name change waits on the user. */
  consentPanel: ReactNode;
}) {
  const api = useApi();
  const [nameInput, setNameInput] = useState("");
  const [nameStatus, setNameStatus] = useState<NameStatus>(null);
  // Guards the one-time path prefill below so it never clobbers later edits.
  const namePrefilled = useRef(false);

  // Debounced availability probe as the user types a new name.
  useEffect(() => {
    const trimmed = nameInput.trim().replace(/^@/, "");
    if (trimmed.length < 2 || !agentDomain) {
      setNameStatus(null);
      return;
    }
    setNameStatus("checking");
    let cancelled = false;
    const timer = setTimeout(() => {
      api
        .checkAgentName(trimmed, agentDomain)
        .then((r) => {
          if (!cancelled) {
            setNameStatus(r.reserved ? "reserved" : r.available ? "available" : "taken");
          }
        })
        .catch(() => {
          if (!cancelled) setNameStatus("error");
        });
    }, 400);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [nameInput, agentDomain, api]);

  // Suggest the DID's own path as the agent name. An agent name's grammar is
  // deliberately identical to a path segment's, so the path is a valid name by
  // construction and is almost always the one the owner wants. Fires once, and
  // only when nothing is bound yet (the first-bind case), so it never overrides
  // a later edit or suggests a name this DID already holds.
  useEffect(() => {
    if (namePrefilled.current || registry === null || nameInput !== "") return;
    // The registry has served + parked names; if it has anything, the owner is
    // adding a further name — leave it blank.
    if (registry.length > 0) return;
    // The root DID has no path segment to borrow.
    if (mnemonic === ".well-known") return;
    const segment = mnemonic.split("/").filter(Boolean).pop() ?? "";
    // Skip a segment that isn't a valid name rather than prefill something the
    // availability check would immediately reject.
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(segment)) return;
    namePrefilled.current = true;
    setNameInput(segment);
  }, [registry, mnemonic, nameInput]);

  const canBind = !publishing && nameStatus === "available";
  const bind = () => {
    const name = nameInput.trim().replace(/^@/, "");
    // The text field never binds the community name: an empty input is "the
    // user has not typed yet", not a request. The button below is the
    // deliberate affordance for it.
    if (!name || !canBind) return;
    if (onBind(name)) {
      setNameInput("");
      setNameStatus(null);
    }
  };

  return (
    <Card title="Agent Names" style={didStyles.card}>
      <Text style={didStyles.hint}>
        A human-memorable shortcut — {agentDomain ? `${agentDomain}/@name` : "yourdomain/@name"} —
        that redirects to this DID. A name is served because the signed document claims it via
        alsoKnownAs, so binding one publishes a new version through your agent.
      </Text>

      {boundNames.length > 0 ? (
        <View style={styles.list}>
          {boundNames.map((name) => {
            const label = agentNameLabel(name, agentDomain);
            return (
              <View key={name} style={didStyles.spread}>
                {/* The community name has no local part, so `@` alone would
                    read as a stray character next to Park/Remove. Spell it as
                    the FAQ writes it — `domain/@`. */}
                <Text style={didStyles.mono}>{label}</Text>
                <View style={didStyles.row}>
                  <Button
                    size="sm"
                    variant="secondary"
                    label="Park"
                    accessibilityLabel={`Park ${label}`}
                    disabled={publishing}
                    onPress={() => onPark(name)}
                  />
                  <Button
                    size="sm"
                    variant="secondary"
                    label="Remove"
                    accessibilityLabel={`Remove ${label}`}
                    disabled={publishing}
                    onPress={() => onUnbind(name)}
                  />
                </View>
              </View>
            );
          })}
        </View>
      ) : (
        <Text style={[didStyles.hint, { marginTop: spacing.sm }]}>No names bound yet.</Text>
      )}

      {/* No domain means we cannot scope a name — names are domain-scoped, so
          `@alice` is meaningless without one. Say what is actually missing. */}
      {!agentDomain ? (
        <Text style={[didStyles.hint, { marginTop: spacing.md }]}>
          {hasDidId
            ? "This DID's hosting domain could not be determined, so a name cannot be scoped to it."
            : "This DID has no published document yet — publish one before binding a name."}
        </Text>
      ) : canDelegate ? (
        <View style={didStyles.stack}>
          <View style={didStyles.row}>
            <Text style={styles.at} aria-hidden>
              @
            </Text>
            <Field
              label="Agent name to bind"
              hideLabel
              value={nameInput}
              onChangeText={setNameInput}
              placeholder="alice"
              autoCapitalize="none"
              autoCorrect={false}
              editable={!publishing}
              onSubmit={bind}
              style={styles.nameField}
              inputStyle={styles.nameInput}
            />
            <Button
              label="Bind name"
              busy={publishing}
              busyLabel="Asking your agent..."
              disabled={!canBind}
              onPress={bind}
            />
          </View>
          {nameStatus && (
            <Text
              aria-live="polite"
              style={[
                styles.status,
                {
                  color:
                    nameStatus === "available"
                      ? colors.success
                      : nameStatus === "checking"
                        ? colors.textSecondary
                        : colors.error,
                },
              ]}
            >
              {STATUS_TEXT[nameStatus]}
            </Text>
          )}
          {/* The community name gets its own control rather than a spelling in
              the text field above. It is a single specific name, not something
              to type, and an empty input already means "nothing entered yet" —
              overloading it would make an accidental Enter publish a document
              version. Root DID only: the control plane binds `{domain}/@` to
              `.well-known` structurally. */}
          {canBindCommunityName && (
            <View style={[didStyles.stack, { marginTop: spacing.lg }]}>
              <Text style={didStyles.hint}>
                This is the domain&apos;s root DID, so it can also hold the community name —{" "}
                {agentDomain}/@ — which identifies the trust community that owns {agentDomain}.
              </Text>
              <Button
                size="sm"
                variant="secondary"
                label={`Bind ${agentDomain}/@`}
                busy={publishing}
                busyLabel="Asking your agent..."
                onPress={onBindCommunityName}
                style={styles.alignStart}
              />
            </View>
          )}

          {/* Parked names, from the host's authoritative registry — they're
              deliberately absent from the document, so this is the only place
              they can come from. */}
          {parkedNames.length > 0 && (
            <View style={styles.list}>
              <Text style={didStyles.hint}>
                Parked — reserved to this DID, not currently served.
              </Text>
              {parkedNames.map((name) => {
                const label = agentNameLabel(name, agentDomain);
                return (
                  <View key={name} style={didStyles.spread}>
                    <Text style={[didStyles.mono, styles.parked]}>{label}</Text>
                    <Button
                      size="sm"
                      variant="secondary"
                      label="Resume"
                      accessibilityLabel={`Resume ${label}`}
                      disabled={publishing}
                      onPress={() => onResume(name)}
                    />
                  </View>
                );
              })}
            </View>
          )}
          {consentPanel}
        </View>
      ) : (
        <Text style={[didStyles.hint, { marginTop: spacing.md }]}>
          Binding a name needs a connected agent wallet to sign the update.
        </Text>
      )}
    </Card>
  );
}

const styles = StyleSheet.create({
  list: {
    gap: spacing.sm,
    marginTop: spacing.md,
  },
  at: {
    color: colors.textSecondary,
    fontFamily: fonts.mono,
  },
  nameField: {
    flex: 1,
    marginBottom: 0,
  },
  nameInput: {
    fontFamily: fonts.mono,
    backgroundColor: colors.bgPrimary,
  },
  status: {
    fontSize: 13,
  },
  parked: {
    color: colors.textSecondary,
  },
  alignStart: {
    alignSelf: "flex-start",
  },
});
