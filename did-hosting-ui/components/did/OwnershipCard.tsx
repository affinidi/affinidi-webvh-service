import { useState } from "react";
import { Text } from "react-native";

import { confirm } from "../../lib/feedback";
import type { DidRecord } from "../../lib/api";
import { errorMessage } from "../../lib/errors";
import { formatDate } from "../../lib/time";
import { useApi } from "../ApiProvider";
import { Button } from "../Button";
import { Card } from "../Card";
import { Field } from "../Field";
import { didStyles } from "./styles";

/**
 * Hand this DID to another identity. An admin transfers it outright; its owner
 * offers it, and it moves when the recipient accepts.
 */
export function OwnershipCard({
  mnemonic,
  isAdmin,
  onChanged,
  notify,
}: {
  mnemonic: string;
  isAdmin: boolean;
  /** The record as the control plane now holds it. */
  onChanged: (record: DidRecord) => void;
  notify: (title: string, message: string) => void;
}) {
  const api = useApi();
  const [open, setOpen] = useState(false);
  const [newOwner, setNewOwner] = useState("");
  const [changing, setChanging] = useState(false);

  const change = async () => {
    const target = newOwner.trim();
    if (!target || changing) return;
    const ok = await confirm({
      title: isAdmin ? "Transfer ownership?" : "Offer this DID?",
      body: isAdmin
        ? `Transfer ownership of "${mnemonic}" to ${target}? The new owner must have access here, and its domain scope and quota must allow this DID.`
        : `Offer "${mnemonic}" to ${target}? It moves when they accept it from their DID list.`,
      confirmLabel: isAdmin ? "Transfer ownership" : "Send offer",
    });
    if (!ok) return;
    await (async () => {
      setChanging(true);
      try {
        const { record, offer } = await api.changeOwner(mnemonic, target);
        onChanged(record);
        setNewOwner("");
        setOpen(false);
        if (offer) {
          const until = formatDate(offer.expiresAt, { withTime: true, fallback: "" });
          notify(
            "Offer sent",
            `${offer.newOwner} can accept "${mnemonic}" from their DID list${until ? ` until ${until}` : ""}. You stay the owner until then.`,
          );
        } else {
          notify("Success", "DID owner changed");
        }
      } catch (e: unknown) {
        notify("Error", errorMessage(e, "Change owner failed"));
      } finally {
        setChanging(false);
      }
    })();
  };

  return (
    <Card
      title="Ownership"
      style={didStyles.card}
      headerRight={
        <Button
          size="sm"
          variant="secondary"
          label={open ? "Cancel" : "Change Owner"}
          onPress={() => {
            if (open) setNewOwner("");
            setOpen(!open);
          }}
        />
      }
    >
      <Text style={didStyles.hint}>
        {isAdmin
          ? "Transfer this DID to a different identity. The new owner must be in the ACL, with a domain scope and quota that allow this DID."
          : "Offer this DID to a different identity. It moves only when they accept it, within 72 hours."}
      </Text>
      {open && (
        <>
          <Field
            label="New owner DID"
            placeholder="did:webvh:..."
            value={newOwner}
            onChangeText={setNewOwner}
            autoCapitalize="none"
            autoCorrect={false}
            onSubmit={change}
            inputStyle={didStyles.mono}
          />
          <Button
            label={isAdmin ? "Transfer Ownership" : "Offer Ownership"}
            busy={changing}
            busyLabel="Sending..."
            disabled={!newOwner.trim()}
            onPress={change}
          />
        </>
      )}
    </Card>
  );
}
