import * as React from "react";
import Box from "@mui/joy/Box";
import Typography from "@mui/joy/Typography";

// custom
import Layout from "../components/Layout";
import DomainAddIcon from "@mui/icons-material/DomainAdd";
import CasinoIcon from "@mui/icons-material/Casino";
import DeleteIcon from "@mui/icons-material/Delete";
import Header from "../components/Header";
import WarningRoundedIcon from "@mui/icons-material/WarningRounded";

import { Link as RouterLink } from "react-router-dom";

import {
  Alert,
  Button,
  Card,
  CardActions,
  CardContent,
  Container,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  FormHelperText,
  FormLabel,
  Grid,
  IconButton,
  Input,
  LinearProgress,
  Link,
  Modal,
  ModalDialog,
  Sheet,
  Stack,
  Tooltip,
} from "@mui/joy";
import { Key } from "@mui/icons-material";

import { decodeBase64, encodeBase64, createDomain, useAuth } from "../auth";
import { useToast } from "../components/Toast";
import { Domain, PassiveKey } from "../keystore";
import ConfirmDialog from "../components/ConfirmDialog";
import { useTitle } from "../components/useTitle";

export default function ManageAuth() {
  useTitle("Domains");

  const [newDomainOpen, setNewDomainOpen] = React.useState(false);
  const { domains, add, passiveKeys } = useAuth();
  const notify = useToast();

  const addDomain = async (domain: Domain) => {
    try {
      await add(domain);
      setNewDomainOpen(false);
      notify({
        message: `Added ${domain.name} domain`,
        color: "success",
      });
    } catch (err) {
      console.error(err);
      notify({
        message: `Failed to add ${domain.name} domain`,
        color: "danger",
      });
    }
  };

  return (
    <Layout.Root cols={1}>
      <Layout.Header>
        <Header />
      </Layout.Header>

      <Layout.Main sx={{ px: 0 }}>
        <Container maxWidth="md">
          <Box
            sx={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              gap: 2,
              py: 1,
            }}
          >
            <Typography level="h2">Domains</Typography>
            {domains?.length !== 0 && (
              <Button
                onClick={() => setNewDomainOpen(!newDomainOpen)}
                variant="plain"
                color="primary"
                startDecorator={<DomainAddIcon />}
              >
                Add Domain
              </Button>
            )}
          </Box>
          <Box
            sx={{
              display: "grid",
              gridTemplateRows:
                newDomainOpen || domains?.length === 0 ? "1fr" : "0fr",
              transition: "0.2s ease",
              "& > *": {
                overflow: "hidden",
              },
            }}
          >
            <Box sx={{ my: 1 }}>
              <AddNewDomain domains={domains || []} onAddDomain={addDomain} />
            </Box>
          </Box>
          <Grid
            container
            spacing={2}
            sx={{ flexGrow: 1, my: 1 }}
            gridAutoFlow={"dense"}
          >
            {domains?.map((item) => (
              <DomainCard key={item.name} domain={item} />
            ))}
          </Grid>
          {passiveKeys.length > 0 && (
            <Box sx={{ my: 2 }}>
              <Typography level="h2">Decryption-only keys</Typography>
              <Grid
                container
                spacing={2}
                sx={{ flexGrow: 1, my: 1 }}
                gridAutoFlow={"dense"}
              >
                {passiveKeys.map((item) => (
                  <PassiveKeyCard key={item.publicKey} passiveKey={item} />
                ))}
              </Grid>
            </Box>
          )}
        </Container>
      </Layout.Main>
    </Layout.Root>
  );
}

type ConfirmDeleteProps = {
  open: boolean;
  onClose: () => void;
  onConfirm: (completelyRemove: boolean) => void;
  domain: Domain;
};

function ConfirmDeleteDialog({
  open,
  onClose,
  onConfirm,
  domain,
}: ConfirmDeleteProps) {
  return (
    <>
      <Modal open={open} onClose={() => onClose()}>
        <ModalDialog variant="outlined" role="alertdialog">
          <DialogTitle>
            <WarningRoundedIcon />
            Confirmation
          </DialogTitle>
          <Divider />
          <DialogContent>
            <p>
              Are you sure you want to remove <b>{domain.name}</b> domain from
              this browser? You will not be able to access any emails sent to
              this domain. If you want to access them again, you will need to
              add the domain again and re-enter the mnemonic.
            </p>
            <p>
              If you are changing the domain credentials, you can also keep the
              decryption key in this browser to be able to access old emails.
            </p>
          </DialogContent>
          <DialogActions
            sx={{
              flexWrap: "wrap",
              flexDirection: "row",
              justifyContent: {
                xs: "center",
                xl: "flex-end",
              },
            }}
          >
            <Button variant="plain" color="neutral" onClick={() => onClose()}>
              Cancel
            </Button>
            <Button
              variant="solid"
              color="danger"
              onClick={() => onConfirm(true)}
            >
              Completely remove
            </Button>
            <Button
              variant="solid"
              color="primary"
              onClick={() => onConfirm(false)}
            >
              Remove and keep decryption key
            </Button>
          </DialogActions>
        </ModalDialog>
      </Modal>
    </>
  );
}

type PassiveKeyCardProps = {
  passiveKey: PassiveKey;
};

function PassiveKeyCard({ passiveKey }: PassiveKeyCardProps) {
  const { removePassive } = useAuth();

  const [open, setOpen] = React.useState(false);
  const notify = useToast();

  return (
    <>
      <Grid xs={12}>
        <Card
          size="sm"
          sx={{
            p: 2,
            display: "flex",
            flexDirection: "row",
          }}
        >
          <Sheet
            variant="plain"
            sx={(theme) => ({
              borderRadius: "sm",
              backgroundColor: theme.vars.palette.background.level1,
              p: 0.5,
            })}
          >
            <Typography
              level="body-sm"
              textColor="var(--joy-palette-text-secondary)"
              fontFamily="Roboto Mono, monospace"
              sx={{
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                p: 1,
              }}
            >
              {passiveKey.publicKey}
            </Typography>
          </Sheet>

          <ConfirmDialog
            confirmText="Remove key"
            open={open}
            onClose={() => setOpen(false)}
            onConfirm={() => {
              setOpen(false);
              removePassive(passiveKey.publicKey)
                .then(() =>
                  notify({
                    message: `Removed the decryption key`,
                    color: "success",
                  })
                )
                .catch((err) => {
                  console.error(err);
                  notify({
                    message: `Failed to remove the decryption key`,
                    color: "danger",
                  });
                });
            }}
          >
            Are you sure you want to remove this decryption key? You will not be
            able to access any emails that were encrypted with it.
          </ConfirmDialog>
          <Tooltip title="Delete decryption key">
            <IconButton
              size="sm"
              variant="plain"
              color="danger"
              sx={{ p: 1 }}
              onClick={() => setOpen(true)}
            >
              <DeleteIcon />
            </IconButton>
          </Tooltip>
        </Card>
      </Grid>
    </>
  );
}

type DomainCardProps = {
  domain: Domain;
};

function DomainCard({ domain }: DomainCardProps) {
  const { remove, passivize } = useAuth();

  const [open, setOpen] = React.useState(false);
  const { setActiveDomain } = useAuth();
  const notify = useToast();

  const fields = [
    `key=${domain.publicKey}`,
    ...(domain.salt !== "" ? [`salt=${domain.salt}`] : []),
  ];

  const dnsRecords = [
    `_compost.${domain.name}. 3600 IN TXT "${fields.join("; ")}"`,
    `${domain.name}. 3600 IN MX 10 mx.compost.email`,
  ];

  const switchDomain = () => {
    setActiveDomain(domain.name);
  };

  return (
    <>
      <Grid xs={12} md={6}>
        <Card
          size="sm"
          sx={{
            p: 2,
            "&:hover": {
              boxShadow: "md",
              borderColor: "neutral.outlinedHoverBorder",
            },
          }}
        >
          <ConfirmDeleteDialog
            domain={domain}
            open={open}
            onClose={() => setOpen(false)}
            onConfirm={(completelyRemove) => {
              setOpen(false);
              (completelyRemove ? remove : passivize)(domain.name)
                .then(() =>
                  notify({
                    message: `Removed ${domain.name}`,
                    color: "success",
                  })
                )
                .catch((err) => {
                  console.error(err);
                  notify({
                    message: `Failed to remove ${domain.name}`,
                    color: "danger",
                  });
                });
            }}
          ></ConfirmDeleteDialog>
          <Box
            sx={{ display: "flex", justifyContent: "space-between", gap: 1 }}
          >
            <Link
              onClick={switchDomain}
              underline="none"
              level="title-md"
              component={RouterLink}
              to="/"
              overlay
            >
              {domain.name}
            </Link>
            <Tooltip title="Delete domain">
              <IconButton
                size="sm"
                variant="plain"
                color="danger"
                onClick={() => setOpen(true)}
              >
                <DeleteIcon />
              </IconButton>
            </Tooltip>
          </Box>
          <Divider sx={{ my: 1 }} />
          <CardContent>
            <Sheet
              variant="plain"
              sx={(theme) => ({
                borderRadius: "sm",
                backgroundColor: theme.vars.palette.background.level1,
              })}
            >
              {dnsRecords.map((r, i) => (
                <Typography
                  key={i}
                  level="body-sm"
                  textColor="var(--joy-palette-text-secondary)"
                  fontFamily="Roboto Mono, monospace"
                  sx={{
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                    p: 1,
                  }}
                >
                  {r}
                </Typography>
              ))}
            </Sheet>
          </CardContent>
        </Card>
      </Grid>
    </>
  );
}

function generateSalt(): string {
  return encodeBase64(window.crypto.getRandomValues(new Uint8Array(32)));
}

type AddNewDomainProps = {
  domains: Domain[];
  onAddDomain(domain: Domain): Promise<void>;
};

const domainRegex =
  /^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$/;

function AddNewDomain({ domains, onAddDomain }: AddNewDomainProps) {
  const [domain, setDomain] = React.useState("");
  const [mnemonic, setMnemonic] = React.useState("");
  const [salt, setSalt] = React.useState("");
  const [saltPopulated, setSaltPopulated] = React.useState<string | null>(null);

  const minLength = 40;

  const addDomain = async () => {
    const d = await createDomain(domain, mnemonic, salt);
    await onAddDomain(d);

    setDomain("");
    setMnemonic("");
    setSalt("");
    setSaltPopulated(null);
  };

  const prepopulateSalt = async () => {
    try {
      let res = await fetch(
        `/api/v1/domain?domain=${encodeURIComponent(domain)}`
      );
      if (res.ok) {
        let data = await res.json();
        setSaltPopulated(data.salt);
      }
    } catch (err) {}
  };

  let domainValid = domainRegex.test(domain);
  let domainExists = domains.some((d) => d.name === domain);

  let saltValid = false;
  try {
    if (salt.length === 0) {
      saltValid = true;
    } else {
      let bytes = decodeBase64(salt);
      saltValid = bytes.length === 32;
    }
  } catch (err) {}

  return (
    <Card size="sm" sx={{ p: 2 }}>
      <Typography level="title-lg">Add new domain</Typography>
      <CardContent
        sx={{
          display: "grid",
          gridTemplateColumns: "repeat(2, minmax(80px, 1fr))",
          gap: 1.5,
        }}
      >
        <FormControl
          sx={{ gridColumn: "1/-1" }}
          error={(!domainValid || domainExists) && domain.length > 0}
        >
          <FormLabel>Domain name</FormLabel>
          <Input
            slotProps={{
              input: {
                autoCapitalize: "off",
              },
            }}
            value={domain}
            onChange={(event) => {
              setDomain(event.target.value.toLocaleLowerCase());
              setSaltPopulated(null);
            }}
            onBlur={() => {
              if (domainValid && !domainExists) {
                prepopulateSalt();
              }
            }}
          />
          {!domainValid && domain.length > 0 && (
            <FormHelperText>Enter a valid domain name</FormHelperText>
          )}
          {domainExists && (
            <FormHelperText>
              Domain already exists in your list of domains
            </FormHelperText>
          )}
        </FormControl>
        <Typography level="body-xs" sx={{ gridColumn: "1/-1" }}>
          Enter the domain (or subdomain) that you would like to receive emails
          to. Don't have one?{" "}
          <Link
            component="button"
            onClick={() => setDomain("demo.compost.email")}
          >
            Try demo.compost.email
          </Link>{" "}
          with an empty mnemonic and salt to see all the emails that have been
          sent to it.
        </Typography>
        <FormControl sx={{ gridColumn: "1/-1" }}>
          <FormLabel>Mnemonic</FormLabel>
          <Stack
            spacing={0.5}
            sx={{
              "--hue": Math.min(mnemonic.length * 10, 120),
            }}
          >
            <Input
              placeholder="Type in here..."
              autoComplete="new-password"
              slotProps={{
                input: {
                  autoCapitalize: "off",
                },
              }}
              autoCorrect="off"
              startDecorator={<Key />}
              value={mnemonic}
              onChange={(event) => setMnemonic(event.target.value)}
            />
            <LinearProgress
              determinate
              size="sm"
              value={Math.min((mnemonic.length * 100) / minLength, 100)}
              sx={{
                bgcolor: "background.level3",
                color: "hsl(var(--hue) 80% 40%)",
              }}
            />
            <Typography
              level="body-xs"
              sx={{ alignSelf: "flex-end", color: "hsl(var(--hue) 80% 30%)" }}
            >
              {mnemonic.length < 10 && "Very weak"}
              {mnemonic.length >= 10 && mnemonic.length < 20 && "Weak"}
              {mnemonic.length >= 20 && mnemonic.length < 30 && "Strong"}
              {mnemonic.length >= 30 && "Very strong"}
            </Typography>
          </Stack>
        </FormControl>
        <Typography level="body-xs" sx={{ gridColumn: "1/-1" }}>
          Mnemonic is used to derive the private key for the domain which is
          used for authentication and decryption of emails. It is not
          transmitted or stored anywhere once the private key is generated and
          the private keys are only stored in this browser (they are not
          extractable).
        </Typography>
        <Typography level="body-xs" sx={{ gridColumn: "1/-1" }}>
          It is important that you keep this mnemonic safe and secure in order
          to be able to access your emails from another browser.
        </Typography>
        {saltPopulated && (
          <Alert
            color="success"
            sx={{ gridColumn: "1/-1" }}
            endDecorator={
              <Button
                variant="solid"
                color="success"
                sx={{ mr: 1 }}
                onClick={() => {
                  setSalt(saltPopulated);
                }}
              >
                Use it
              </Button>
            }
          >
            <span>
              <b>{domain}</b> already has a salt set in the DNS records.
            </span>
          </Alert>
        )}
        <FormControl sx={{ gridColumn: "1/-1" }} error={!saltValid}>
          <FormLabel>Salt (optional)</FormLabel>
          <Input
            value={salt}
            sx={{ fontFamily: "Roboto Mono, monospace" }}
            onChange={(event) => {
              setSalt(event.target.value);
            }}
            autoComplete="off"
            slotProps={{
              input: {
                autoCapitalize: "off",
              },
            }}
            autoCorrect="off"
            endDecorator={
              <Tooltip title="Generate random salt">
                <IconButton
                  color="primary"
                  variant="solid"
                  onClick={() => {
                    setSalt(generateSalt());
                  }}
                >
                  <CasinoIcon />
                </IconButton>
              </Tooltip>
            }
          />
          {!saltValid && (
            <FormHelperText>
              Salt must be 32 bytes long in base64 encoding.
            </FormHelperText>
          )}
        </FormControl>
        <Typography level="body-xs" sx={{ gridColumn: "1/-1" }}>
          Salt is optionally used for hashing all the object identifiers (domain
          name, email addresses, etc.) on the server side. Selecting a random
          salt makes it harder for link the objects in the database to you if it
          is ever compromised. Note that email bodies are already encrypted, so
          this only protects metadata such as the recepient address.
        </Typography>
        <Typography level="body-xs" sx={{ gridColumn: "1/-1" }}>
          Salt is not secret (it will be publicly available in the DNS records).
        </Typography>
        <CardActions sx={{ gridColumn: "1/-1" }}>
          <Button
            onClick={addDomain}
            variant="solid"
            color="primary"
            disabled={!(domainValid && saltValid && !domainExists)}
          >
            Add domain
          </Button>
        </CardActions>
      </CardContent>
    </Card>
  );
}
