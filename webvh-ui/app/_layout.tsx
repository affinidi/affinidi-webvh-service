import { Stack } from "expo-router";
import { AuthProvider } from "../components/AuthProvider";
import { ApiProvider } from "../components/ApiProvider";

export default function RootLayout() {
  return (
    <AuthProvider>
      <ApiProvider>
        <Stack
          screenOptions={{
            headerStyle: { backgroundColor: "#1a1a2e" },
            headerTintColor: "#e0e0ff",
            headerTitleStyle: { fontWeight: "bold" },
            contentStyle: { backgroundColor: "#0f0f23" },
          }}
        >
          <Stack.Screen name="index" options={{ title: "WebVH Dashboard" }} />
          <Stack.Screen name="login" options={{ title: "Authenticate" }} />
          <Stack.Screen name="dids/index" options={{ title: "DIDs" }} />
          <Stack.Screen name="dids/[mnemonic]" options={{ title: "DID Detail" }} />
          <Stack.Screen name="acl/index" options={{ title: "Access Control" }} />
        </Stack>
      </ApiProvider>
    </AuthProvider>
  );
}
