import { Stack } from "expo-router";
import {
  useFonts,
  Figtree_400Regular,
  Figtree_500Medium,
  Figtree_600SemiBold,
  Figtree_700Bold,
} from "@expo-google-fonts/figtree";
import { ActivityIndicator, View } from "react-native";
import { AuthProvider } from "../components/AuthProvider";
import { ApiProvider } from "../components/ApiProvider";
import { colors } from "../lib/theme";

export default function RootLayout() {
  const [fontsLoaded] = useFonts({
    Figtree_400Regular,
    Figtree_500Medium,
    Figtree_600SemiBold,
    Figtree_700Bold,
  });

  if (!fontsLoaded) {
    return (
      <View
        style={{
          flex: 1,
          backgroundColor: colors.bgPrimary,
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <ActivityIndicator color={colors.accent} size="large" />
      </View>
    );
  }

  return (
    <AuthProvider>
      <ApiProvider>
        <Stack
          screenOptions={{
            headerStyle: { backgroundColor: colors.bgHeader },
            headerTintColor: colors.textPrimary,
            headerTitleStyle: {
              fontWeight: "600",
              fontFamily: "Figtree_600SemiBold",
            },
            contentStyle: { backgroundColor: colors.bgPrimary },
          }}
        >
          <Stack.Screen name="index" options={{ title: "Dashboard" }} />
          <Stack.Screen name="login" options={{ title: "Authenticate" }} />
          <Stack.Screen name="dids/index" options={{ title: "DIDs" }} />
          <Stack.Screen
            name="dids/[mnemonic]"
            options={{ title: "DID Detail" }}
          />
          <Stack.Screen
            name="acl/index"
            options={{ title: "Access Control" }}
          />
          <Stack.Screen
            name="enroll"
            options={{ title: "Enroll Passkey" }}
          />
        </Stack>
      </ApiProvider>
    </AuthProvider>
  );
}
