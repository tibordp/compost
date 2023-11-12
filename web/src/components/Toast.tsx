import { Snackbar, SnackbarProps } from "@mui/joy";
import React from "react";

type ToastProviderProps = {
  children: React.ReactNode;
};

export type NotifyParams = {
  variant?: SnackbarProps["variant"];
  color?: SnackbarProps["color"];
  message: string;
};

type ToastContextType = (params: NotifyParams) => void;
const ToastContext = React.createContext<ToastContextType | null>(null);

export function useToast() {
  const context = React.useContext(ToastContext);
  if (!context) {
    throw new Error(`useToast must be used within a ToastProvider`);
  }
  return context;
}

export function ToastProvider({ children }: ToastProviderProps) {
  const [open, setOpen] = React.useState(false);
  const [variant, setVariant] =
    React.useState<SnackbarProps["variant"]>("solid");
  const [color, setColor] = React.useState<SnackbarProps["color"]>("neutral");
  const [message, setMessage] = React.useState("");

  const notify = ({ variant, message, color }: NotifyParams) => {
    setMessage(message);
    setVariant(variant || "solid");
    setColor(color || "neutral");
    setOpen(true);
  };

  return (
    <>
      <ToastContext.Provider value={notify}>{children}</ToastContext.Provider>
      <Snackbar
        autoHideDuration={3000}
        open={open}
        variant={variant}
        color={color}
        onClose={(_event, reason) => {
          if (reason === "clickaway") {
            return;
          }
          setOpen(false);
        }}
      >
        {message}
      </Snackbar>
    </>
  );
}
