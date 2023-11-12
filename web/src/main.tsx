import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import ManageAuth from "./pages/ManageAuth.tsx";

import "@fontsource/inter";
import { RouterProvider, createBrowserRouter } from "react-router-dom";
import { AuthProvider, getAuth } from "./auth";
import { ToastProvider } from "./components/Toast.tsx";
import NotFound from "./pages/NotFound.tsx";
import { CssBaseline, CssVarsProvider } from "@mui/joy";
import About from "./pages/About.tsx";
import Email from "./pages/Email.tsx";
import { getPassiveKeys } from "./keystore.ts";
import { GlobalStyles } from "@mui/material";

import "@fontsource/roboto-mono/index.css";

const queryClient = new QueryClient();
const router = createBrowserRouter([
  {
    path: "/mail/:account/:email",
    element: <Email />,
  },
  {
    path: "/mail/:account",
    element: <Email />,
  },
  {
    path: "/domains",
    element: <ManageAuth />,
  },
  {
    path: "/",
    element: <Email />,
  },
  {
    path: "/about",
    element: <About />,
  },
  {
    path: "*",
    element: <NotFound />,
  },
]);

let auth = null;
try {
  auth = await getAuth();
} catch (e) {}
const passiveKeys = await getPassiveKeys();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AuthProvider initialAuth={auth} initialPassiveKeys={passiveKeys}>
      <ToastProvider>
        <QueryClientProvider client={queryClient}>
          <CssVarsProvider disableTransitionOnChange>
            <CssBaseline />
            <GlobalStyles
              styles={{ code: { fontFamily: "Roboto Mono, monospace" } }}
            />
            <RouterProvider router={router} />
          </CssVarsProvider>
        </QueryClientProvider>
      </ToastProvider>
    </AuthProvider>
  </React.StrictMode>
);
