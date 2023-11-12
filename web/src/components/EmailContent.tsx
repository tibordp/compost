import * as React from "react";
import Box from "@mui/joy/Box";
import Chip from "@mui/joy/Chip";
import Card from "@mui/joy/Card";
import CardOverflow from "@mui/joy/CardOverflow";
import Sheet from "@mui/joy/Sheet";
import Typography from "@mui/joy/Typography";
import Button from "@mui/joy/Button";
import AspectRatio from "@mui/joy/AspectRatio";
import Divider from "@mui/joy/Divider";
import Tooltip from "@mui/joy/Tooltip";

import { Letter } from "react-letter";
import { LetterparserAttachment, extract } from "letterparser";

// Icons import
import FolderIcon from "@mui/icons-material/Folder";
import InfoIcon from "@mui/icons-material/Info";
import MenuIcon from "@mui/icons-material/Menu";
import CloseIcon from "@mui/icons-material/Close";
import { useBlob } from "../query";
import { Link as RouterLink } from "react-router-dom";
import {
  Alert,
  Dropdown,
  IconButton,
  Link,
  Menu,
  MenuButton,
  MenuItem,
  Skeleton,
} from "@mui/joy";
import { formatFileSize } from "../util";
import MagicAvatar from "./MagicAvatar";

type EmailContentProps = {
  account: string;
  email: string;
};

export default function EmailContent({ account, email }: EmailContentProps) {
  const { isPending, error, data } = useBlob(account, email);
  const [allowExternalResources, setAllowExternalResources] = React.useState<
    boolean | null
  >(null);
  const [hasExternalResources, setHasExternalResources] = React.useState(false);

  const parsed = React.useMemo(() => {
    if (!data) {
      return null;
    }
    return extract(data);
  }, [data]);

  React.useEffect(() => {
    setAllowExternalResources(null);
    setHasExternalResources(false);
  }, [parsed]);

  const blockRewriter = (url: string) => {
    if (!hasExternalResources) {
      // Detect external resources during first render
      setHasExternalResources(true);
    }
    return allowExternalResources ? url : "";
  };

  const showBlockAlert =
    hasExternalResources && allowExternalResources === null;

  return (
    <Sheet
      variant="outlined"
      sx={{
        borderRadius: "sm",
        p: 2,
        mb: 3,
      }}
    >
      <Header
        isPending={isPending}
        parsed={parsed}
        error={error}
        account={account}
        id={email}
        raw={data}
      />
      <Divider sx={{ mt: 2 }} />
      <Box
        sx={{
          py: 2,
          display: "flex",
          flexDirection: "column",
          alignItems: "start",
        }}
      >
        {error && (
          <Alert color="warning" variant="soft" sx={{ width: "100%" }}>
            {error.message}
          </Alert>
        )}
        {!error && (
          <Typography level="title-lg" textColor="text.primary">
            <Skeleton loading={isPending}>
              {parsed?.subject || "<no subject>"}
            </Skeleton>
          </Typography>
        )}

        <Box
          sx={{
            mt: 1,
            display: "flex",
            alignItems: "center",
            gap: 1,
            flexWrap: "wrap",
          }}
        >
          {isPending && (
            <Typography
              component="span"
              level="body-sm"
              sx={{ mr: 1, display: "inline-block" }}
            >
              <Skeleton loading={isPending}>Unknown recepient</Skeleton>
            </Typography>
          )}
          {parsed && (
            <>
              <div>
                <Typography
                  component="span"
                  level="body-sm"
                  sx={{ mr: 1, display: "inline-block" }}
                >
                  From
                </Typography>
                <Tooltip size="sm" title="Copy email">
                  <Chip
                    size="sm"
                    variant="soft"
                    color="primary"
                    onClick={() => {}}
                  >
                    {parsed?.from?.address || "Unknown"}
                  </Chip>
                </Tooltip>
              </div>
              <div>
                <Typography
                  component="span"
                  level="body-sm"
                  sx={{ mr: 1, display: "inline-block" }}
                >
                  to
                </Typography>
                {parsed?.to?.map((recepient, i) => (
                  <Tooltip
                    size="sm"
                    title="Copy email"
                    variant="outlined"
                    key={i}
                  >
                    <Chip
                      size="sm"
                      variant="soft"
                      color="primary"
                      onClick={() => {}}
                    >
                      {recepient.address || "Unknown"}
                    </Chip>
                  </Tooltip>
                ))}
              </div>
            </>
          )}
        </Box>
      </Box>

      {showBlockAlert ? (
        <Alert
          startDecorator={<InfoIcon />}
          variant="soft"
          color="neutral"
          endDecorator={
            <React.Fragment>
              <Button
                onClick={() => {
                  setAllowExternalResources(true);
                }}
                variant="plain"
                color="neutral"
                sx={{ mr: 1 }}
              >
                Allow
              </Button>
              <IconButton
                variant="soft"
                size="sm"
                color="neutral"
                onClick={() => {
                  setAllowExternalResources(false);
                }}
              >
                <CloseIcon />
              </IconButton>
            </React.Fragment>
          }
        >
          External resources have been blocked for this email.
        </Alert>
      ) : (
        <Divider />
      )}

      {parsed && (
        <>
          <Box sx={{ py: 1, overflowY: "auto" }}>
            <Letter
              html={parsed?.html || ""}
              text={parsed?.text || ""}
              rewriteExternalResources={blockRewriter}
            />
          </Box>
          <Divider />
        </>
      )}
      {parsed?.attachments && parsed.attachments.length > 0 && (
        <Attachments attachments={parsed.attachments} />
      )}
    </Sheet>
  );
}

type HeaderProps = {
  isPending: boolean;
  id: string;
  parsed: ReturnType<typeof extract> | null;
  error: Error | null;
  account: string;
  raw?: string;
};

function Header({ isPending, parsed, account, raw, id }: HeaderProps) {
  const url = React.useMemo(() => {
    if (!raw) {
      return "";
    }

    const data = new Blob([raw], { type: "message/rfc822" });
    return URL.createObjectURL(data);
  }, [raw]);

  return (
    <Box
      sx={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: 2,
      }}
    >
      <Box sx={{ display: "flex", justifyContent: "space-between" }}>
        <MagicAvatar name={parsed?.from?.name} />
        <Box sx={{ ml: 2 }}>
          <Typography level="title-sm" textColor="text.primary" mb={0.5}>
            <Skeleton loading={isPending}>
              {!parsed && "Unknown"}
              {parsed &&
                (parsed.from?.name || parsed.from?.address || "Unknown")}
            </Skeleton>
          </Typography>
          <Typography level="body-xs" textColor="text.tertiary">
            <Skeleton loading={isPending}>
              {!parsed && "Unknown"}
              {parsed?.date?.toLocaleString(undefined, {
                weekday: "short",
                year: "numeric",
                month: "short",
                day: "numeric",
                hour: "numeric",
                minute: "numeric",
              })}
            </Skeleton>
          </Typography>
        </Box>
      </Box>
      <Box
        sx={{
          display: "flex",
          height: "32px",
          flexDirection: "row",
          gap: 1.5,
        }}
      >
        {raw && (
          <Dropdown>
            <MenuButton variant="plain" size="sm">
              <MenuIcon />
            </MenuButton>
            <Menu
              placement="bottom-end"
              size="sm"
              sx={{
                zIndex: "99999",
                p: 1,
                gap: 1,
                "--ListItem-radius": "var(--joy-radius-sm)",
              }}
            >
              <MenuItem component={Link} download={`${id}.eml`} href={url}>
                Download
              </MenuItem>
            </Menu>
          </Dropdown>
        )}
        <IconButton
          variant="plain"
          size="sm"
          component={RouterLink}
          to={`/mail/${account}`}
        >
          <CloseIcon />
        </IconButton>
      </Box>
    </Box>
  );
}

type AttachmentsProps = {
  attachments: LetterparserAttachment[];
};

function Attachments({ attachments }: AttachmentsProps): React.ReactNode {
  return (
    <>
      <Typography level="title-sm" mt={2} mb={2}>
        Attachments
      </Typography>
      <Box
        sx={(theme) => ({
          display: "flex",
          flexWrap: "wrap",
          gap: 2,
          "& > div": {
            boxShadow: "none",
            "--Card-padding": "0px",
            "--Card-radius": theme.vars.radius.sm,
          },
        })}
      >
        {attachments.map((attachment, i) => (
          <React.Fragment key={i}>
            {attachment.contentType.type.startsWith("image/") && (
              <ImageAttachment
                filename={attachment.filename}
                contentType={attachment.contentType.type}
                body={attachment.body}
              />
            )}
            {!attachment.contentType.type.startsWith("image/") && (
              <OtherAttachment
                filename={attachment.filename}
                contentType={attachment.contentType.type}
                body={attachment.body}
              />
            )}
          </React.Fragment>
        ))}
      </Box>
    </>
  );
}

type AttachmentProps = {
  filename?: string;
  contentType: string;
  body: Uint8Array | string;
};

function ImageAttachment({ filename, contentType, body }: AttachmentProps) {
  const url = React.useMemo(() => {
    let blob = new Blob([body], { type: contentType });
    return URL.createObjectURL(blob);
  }, [body, contentType]);

  return (
    <Card variant="outlined">
      <AspectRatio ratio="1" sx={{ minWidth: 80 }}>
        <a href={url} download={filename}>
          <img src={url} alt={filename} />
        </a>
      </AspectRatio>
    </Card>
  );
}

function OtherAttachment({ filename, contentType, body }: AttachmentProps) {
  const url = React.useMemo(() => {
    let blob = new Blob([body], { type: contentType });
    return URL.createObjectURL(blob);
  }, [body, contentType]);

  return (
    <Card variant="outlined" orientation="horizontal">
      <CardOverflow>
        <AspectRatio ratio="1" sx={{ minWidth: 80 }}>
          <a href={url} download={filename}>
            <div>
              <FolderIcon />
            </div>
          </a>
        </AspectRatio>
      </CardOverflow>
      <Box sx={{ py: { xs: 1, sm: 2 }, pr: 2 }}>
        <Typography level="title-sm" color="primary">
          <Link href={url} download={filename}>
            {filename}
          </Link>
        </Typography>
        <Typography level="body-xs">{formatFileSize(body.length)}</Typography>
      </Box>
    </Card>
  );
}
