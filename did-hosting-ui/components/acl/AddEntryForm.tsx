import { useCallback, useEffect, useState } from "react";
import { StyleSheet, Text, View } from "react-native";

import type { Role } from "../../lib/api";
import {
  DEFAULT_SCOPE_DRAFT,
  defaultScopeForRole,
  draftToScope,
  validateScopeDraft,
  type ScopeDraft,
} from "../../lib/acl-scope";
import { showAlert } from "../../lib/alert";
import { errorMessage } from "../../lib/errors";
import { parseMbToBytes, parseOptionalInt } from "../../lib/format";
import { invalidateQueries } from "../../lib/query";
import { colors, fonts, spacing } from "../../lib/theme";
import { useApi } from "../ApiProvider";
import { Button } from "../Button";
import { Card } from "../Card";
import { useDomains } from "../DomainProvider";
import { Field } from "../Field";
import { SegmentedControl } from "../SegmentedControl";
import { ACL_KEY } from "./keys";
import { ENTRY_ROLES } from "./roles";
import { ScopeEditor, type AvailableDomain } from "./ScopeEditor";

/** Add an ACL entry: a DID or an agent name hosted here, a role, quotas, scope. */
export function AddEntryForm({ availableDomains }: { availableDomains: AvailableDomain[] }) {
  const api = useApi();
  const { defaultDomain } = useDomains();
  const [did, setDid] = useState("");
  const [role, setRole] = useState<Role>("owner");
  const [label, setLabel] = useState("");
  const [maxTotalSize, setMaxTotalSize] = useState("");
  const [maxDidCount, setMaxDidCount] = useState("");
  const [scope, setScope] = useState<ScopeDraft>(DEFAULT_SCOPE_DRAFT);
  // Whether the operator has touched the scope editor for the entry being
  // built — once true, the effect below stops overwriting `scope`.
  const [scopeTouched, setScopeTouched] = useState(false);
  const [creating, setCreating] = useState(false);

  // See `defaultScopeForRole`. Runs only while the operator hasn't picked a
  // scope themselves, and only for the "Add Entry" form — editing an
  // existing entry's role never rewrites its scope, matching the removed
  // route's `PUT` behaviour, which had no such default either.
  useEffect(() => {
    if (scopeTouched) return;
    setScope(defaultScopeForRole(role, defaultDomain));
  }, [role, defaultDomain, scopeTouched]);

  const handleScopeChange = useCallback((next: ScopeDraft) => {
    setScopeTouched(true);
    setScope(next);
  }, []);

  const scopeError = validateScopeDraft(scope);
  const canSubmit = !!did.trim() && !creating && !scopeError;

  const handleCreate = async () => {
    if (!did.trim() || creating) return;
    if (scopeError) {
      showAlert("Invalid scope", scopeError);
      return;
    }
    setCreating(true);
    try {
      await api.createAcl(did.trim(), role, {
        label: label.trim() || undefined,
        maxTotalSize: parseMbToBytes(maxTotalSize) ?? undefined,
        maxDidCount: parseOptionalInt(maxDidCount) ?? undefined,
        domains: draftToScope(scope),
      });
      setDid("");
      setLabel("");
      setMaxTotalSize("");
      setMaxDidCount("");
      setScopeTouched(false);
      await invalidateQueries(ACL_KEY);
    } catch (e: unknown) {
      showAlert("Error", errorMessage(e, "Failed to create ACL entry"));
    } finally {
      setCreating(false);
    }
  };

  return (
    <Card title="Add Entry" style={styles.card}>
      {/* Names are resolved once, when the entry is created; the entry is
          stored against the DID. Said plainly here because otherwise an
          operator could reasonably assume access follows the name, and be
          surprised either way — that it does not move when the name does,
          or that it might. */}
      <Field
        label="DID or agent name"
        placeholder="did:web:example.com  or  example.com/@alice"
        value={did}
        onChangeText={setDid}
        autoCapitalize="none"
        autoCorrect={false}
        hint="A DID, or an agent name hosted here — the name is resolved now and the entry is stored against the DID it points at today."
        onSubmit={handleCreate}
      />
      <SegmentedControl
        label="Role"
        options={ENTRY_ROLES}
        value={role}
        onChange={setRole}
        style={styles.row}
      />
      <Field
        label="Label (optional)"
        placeholder="Label (optional)"
        value={label}
        onChangeText={setLabel}
        onSubmit={handleCreate}
      />
      <View style={styles.quotaRow}>
        <Field
          label="Max total size (MB)"
          placeholder="Default"
          value={maxTotalSize}
          onChangeText={setMaxTotalSize}
          keyboardType="numeric"
          onSubmit={handleCreate}
          style={styles.half}
        />
        <Field
          label="Max DID count"
          placeholder="Default"
          value={maxDidCount}
          onChangeText={setMaxDidCount}
          keyboardType="numeric"
          onSubmit={handleCreate}
          style={styles.half}
        />
      </View>
      <Text style={styles.quotaHint}>Leave blank to use server default</Text>
      <ScopeEditor draft={scope} availableDomains={availableDomains} onChange={handleScopeChange} />
      <Button
        label="Add Entry"
        busyLabel="Adding..."
        busy={creating}
        disabled={!canSubmit && !creating}
        onPress={handleCreate}
      />
    </Card>
  );
}

const styles = StyleSheet.create({
  card: {
    marginBottom: spacing.xl,
  },
  row: {
    marginBottom: spacing.md,
  },
  quotaRow: {
    flexDirection: "row",
    gap: spacing.sm,
  },
  half: {
    flex: 1,
  },
  quotaHint: {
    fontSize: 12,
    fontFamily: fonts.regular,
    color: colors.textTertiary,
    marginBottom: spacing.md,
  },
});
