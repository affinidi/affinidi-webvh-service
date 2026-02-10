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
import { NavBar } from "../components/NavBar";
import { colors } from "../lib/theme";

function AppHeader() {
  return <NavBar />;
}

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
            header: () => <AppHeader />,
            contentStyle: { backgroundColor: colors.bgPrimary },
          }}
        >
          <Stack.Screen name="index" />
          <Stack.Screen name="login" />
          <Stack.Screen name="dids/index" />
          <Stack.Screen name="dids/[mnemonic]" />
          <Stack.Screen name="acl/index" />
          <Stack.Screen name="enroll" />
        </Stack>
      </ApiProvider>
    </AuthProvider>
  );
}
