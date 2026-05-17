import React, { createContext, useContext } from "react";
import { api } from "../lib/api";

/**
 * Provides the typed API client via React context.
 * Currently just re-exports the singleton, but allows for future
 * configuration (e.g. different base URLs per environment).
 */
const ApiContext = createContext(api);

export function ApiProvider({ children }: { children: React.ReactNode }) {
  return <ApiContext.Provider value={api}>{children}</ApiContext.Provider>;
}

export function useApi() {
  return useContext(ApiContext);
}
