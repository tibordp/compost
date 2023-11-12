import Button from "@mui/joy/Button";
import Divider from "@mui/joy/Divider";
import DialogTitle from "@mui/joy/DialogTitle";
import DialogContent from "@mui/joy/DialogContent";
import DialogActions from "@mui/joy/DialogActions";
import Modal from "@mui/joy/Modal";
import ModalDialog from "@mui/joy/ModalDialog";
import WarningRoundedIcon from "@mui/icons-material/WarningRounded";
import React from "react";

type AlertDialogModalProps = {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  confirmText?: string;
  children: React.ReactNode;
};

export default function ConfirmDialog({
  open,
  onClose,
  onConfirm,
  confirmText,
  children,
}: AlertDialogModalProps) {
  return (
    <>
      <Modal open={open} onClose={() => onClose()}>
        <ModalDialog variant="outlined" role="alertdialog">
          <DialogTitle>
            <WarningRoundedIcon />
            Confirmation
          </DialogTitle>
          <Divider />
          <DialogContent>{children}</DialogContent>
          <DialogActions>
            <Button variant="solid" color="danger" onClick={() => onConfirm()}>
              {confirmText}
            </Button>
            <Button variant="plain" color="neutral" onClick={() => onClose()}>
              Cancel
            </Button>
          </DialogActions>
        </ModalDialog>
      </Modal>
    </>
  );
}
