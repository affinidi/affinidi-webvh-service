import { useState } from "react";
import { Text } from "react-native";

import { errorMessage } from "../../lib/errors";
import { useApi } from "../ApiProvider";
import { Button } from "../Button";
import { Card } from "../Card";
import { Field } from "../Field";
import { didStyles } from "./styles";

/**
 * Upload a signed `did.jsonl` or a witness proof by hand — for an operator
 * who builds the log themselves rather than through an agent.
 */
export function UploadCards({
  mnemonic,
  versionCount,
  logContent,
  onLogContentChange,
  loadingRaw,
  onLoadCurrent,
  onUploaded,
  notify,
}: {
  mnemonic: string;
  /** Log versions held; "Load Current JSONL" is offered once there is one. */
  versionCount: number;
  /** The log textarea — lifted, so the document card can fill it. */
  logContent: string;
  onLogContentChange: (value: string) => void;
  loadingRaw: boolean;
  onLoadCurrent: () => void;
  /** After a log upload: reload what the page shows. */
  onUploaded: () => void;
  notify: (title: string, message: string) => void;
}) {
  const api = useApi();
  const [witnessContent, setWitnessContent] = useState("");
  const [uploading, setUploading] = useState(false);

  const uploadLog = async () => {
    if (!logContent.trim()) return;
    setUploading(true);
    try {
      await api.uploadDid(mnemonic, logContent);
      notify("Success", "DID log uploaded successfully");
      onLogContentChange("");
      onUploaded();
    } catch (e: unknown) {
      notify("Error", errorMessage(e, "Upload failed"));
    } finally {
      setUploading(false);
    }
  };

  const uploadWitness = async () => {
    if (!witnessContent.trim()) return;
    setUploading(true);
    try {
      await api.uploadWitness(mnemonic, witnessContent);
      notify("Success", "Witness proof uploaded successfully");
      setWitnessContent("");
    } catch (e: unknown) {
      notify("Error", errorMessage(e, "Upload failed"));
    } finally {
      setUploading(false);
    }
  };

  return (
    <>
      <Card title="Upload DID Log" style={didStyles.card}>
        <Text style={didStyles.hint}>Paste the JSONL content for the did.jsonl file.</Text>
        {versionCount > 0 && (
          <Button
            variant="secondary"
            label="Load current did.jsonl into this box"
            busy={loadingRaw}
            busyLabel="Loading..."
            onPress={onLoadCurrent}
            style={{ marginBottom: 12 }}
          />
        )}
        <Field
          label="DID log (JSONL)"
          hideLabel
          placeholder='{"versionId":"1",...}'
          value={logContent}
          onChangeText={onLogContentChange}
          multiline
          inputStyle={didStyles.textarea}
        />
        <Button
          label="Upload DID Log"
          busy={uploading}
          busyLabel="Uploading..."
          disabled={!logContent.trim()}
          onPress={() => void uploadLog()}
        />
      </Card>

      <Card title="Upload Witness Proof" style={didStyles.card}>
        <Text style={didStyles.hint}>Paste the JSON content for the witness proof.</Text>
        <Field
          label="Witness proof (JSON)"
          hideLabel
          placeholder='{"witness":...}'
          value={witnessContent}
          onChangeText={setWitnessContent}
          multiline
          inputStyle={didStyles.textarea}
        />
        <Button
          label="Upload Witness"
          busy={uploading}
          busyLabel="Uploading..."
          disabled={!witnessContent.trim()}
          onPress={() => void uploadWitness()}
        />
      </Card>
    </>
  );
}
