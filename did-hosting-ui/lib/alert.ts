import { Platform, Alert } from "react-native";

/** Show an informational alert (works on web and native). */
export function showAlert(title: string, message: string) {
  if (Platform.OS === "web") {
    window.alert(message);
  } else {
    Alert.alert(title, message);
  }
}

/** Show a confirmation dialog; calls `onConfirm` if user accepts, `onCancel` if declined. */
export function showConfirm(
  title: string,
  message: string,
  onConfirm: () => void,
  onCancel?: () => void,
) {
  if (Platform.OS === "web") {
    if (window.confirm(message)) {
      onConfirm();
    } else {
      onCancel?.();
    }
  } else {
    Alert.alert(title, message, [
      { text: "Cancel", style: "cancel", onPress: onCancel },
      { text: "OK", style: "destructive", onPress: onConfirm },
    ]);
  }
}
