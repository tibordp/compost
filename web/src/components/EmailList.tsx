import * as React from "react";
import Box from "@mui/joy/Box";
import Typography from "@mui/joy/Typography";
import Avatar from "@mui/joy/Avatar";
import List from "@mui/joy/List";
import ListDivider from "@mui/joy/ListDivider";
import ListItem from "@mui/joy/ListItem";
import ListItemButton, { listItemButtonClasses } from "@mui/joy/ListItemButton";
import ListItemDecorator from "@mui/joy/ListItemDecorator";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import { Link } from "react-router-dom";
import { InboxEntry, useAccounts, useEmailList } from "../query";
import { Alert, Chip, LinearProgress } from "@mui/joy";
import MagicAvatar from "./MagicAvatar";

type EmailListProps = {
  account?: string;
  email?: string;
};

export default function EmailList({ account, email }: EmailListProps) {
  const {
    isPending: emailsPending,
    error: emailsError,
    data,
  } = useEmailList(account);
  const {
    data: accountData,
    isPending: accountsPending,
    error: accountsError,
  } = useAccounts();

  const isPending = emailsPending || accountsPending;
  const error = emailsError || accountsError;

  const displayEmail = accountData?.find((i) => i.id === account)?.email;

  const header = (
    <Box
      sx={{
        p: 2,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}
    >
      <Typography level="title-lg" textColor="text.secondary">
        {displayEmail}
        {!displayEmail && !account && `All accounts`}
        {!displayEmail && account && `Unknown account`}
      </Typography>
    </Box>
  );

  return (
    <>
      {header}
      {(isPending || error || data?.length === 0) && (
        <Box sx={{ px: 2, display: "flex", flexDirection: "column", gap: 1 }}>
          {isPending && <LinearProgress />}
          {!isPending && error && (
            <Alert color="warning" variant="soft">
              {error.message}
            </Alert>
          )}
          {!isPending && !error && data?.length === 0 && (
            <Alert color="neutral" variant="soft">
              No emails found, go ahead and receive some!
            </Alert>
          )}
        </Box>
      )}
      <List
        sx={{
          [`& .${listItemButtonClasses.root}.${listItemButtonClasses.selected}`]:
            {
              borderLeft: "2px solid",
              borderLeftColor: "var(--joy-palette-primary-outlinedBorder)",
            },
        }}
      >
        {data?.map((item) => (
          <React.Fragment key={item.id}>
            <EmailListItem
              recepient={
                account
                  ? undefined
                  : accountData?.find((i) => i.id === item.account_id)?.email ||
                    "Unknown recipient"
              }
              selected={!!email && email === item.id}
              item={item}
            />
            <ListDivider sx={{ m: 0 }} />
          </React.Fragment>
        ))}
      </List>
      <Box sx={{ display: "flex" }}></Box>
    </>
  );
}

type EmailListItemProps = {
  recepient?: string;

  selected: boolean;
  item: InboxEntry;
};

function EmailListItem({ selected, item, recepient }: EmailListItemProps) {
  const metadata = item.metadata;
  if (!metadata) {
    return (
      <ListItem>
        <ListItemButton
          {...(selected && {
            selected: true,
            color: "neutral",
          })}
          component={Link}
          to={`/mail/${item.account_id}/${item.id}`}
          sx={{ p: 2 }}
        >
          <ListItemDecorator sx={{ alignSelf: "flex-start" }}>
            <Avatar children={<LockOutlinedIcon />} />
          </ListItemDecorator>
          <Box sx={{ pl: 2, width: "100%" }}>
            <Typography level="title-sm">Could not decrypt</Typography>
          </Box>
          {recepient && (
            <Chip size="sm" variant="soft" color="primary" onClick={() => {}}>
              {recepient}
            </Chip>
          )}
        </ListItemButton>
      </ListItem>
    );
  }

  const from = metadata.from
    .map((i) => {
      return i.name || i.address || "unknown";
    })
    .join(", ");

  return (
    <ListItem>
      <ListItemButton
        {...(selected && {
          selected: true,
          color: "neutral",
        })}
        component={Link}
        to={`/mail/${item.account_id}/${item.id}`}
        sx={{ p: 2, minHeight: 0 }}
      >
        <ListItemDecorator sx={{ alignSelf: "flex-start" }}>
          <MagicAvatar name={from} />
        </ListItemDecorator>
        <Box sx={{ pl: 2, width: "100%" }}>
          <Box
            sx={{
              display: "flex",
              justifyContent: "space-between",

              minWidth: 0,
            }}
          >
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                minWidth: 0,
                gap: 0.5,
              }}
            >
              <Typography
                level="body-xs"
                sx={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  minWidth: 0,
                }}
              >
                {from}
              </Typography>
            </Box>

            <Typography level="body-xs" textColor="text.tertiary">
              {new Date(metadata.datetime).toLocaleString(undefined, {
                weekday: "short",
                year: "numeric",
                month: "short",
                day: "numeric",
                hour: "numeric",
                minute: "numeric",
              })}
            </Typography>
          </Box>
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 0.5,
            }}
          >
            <Typography
              level="title-sm"
              sx={{
                mb: 0.5,
                overflow: "hidden",
                textOverflow: "ellipsis",
                minWidth: 0,
              }}
            >
              {metadata.subject}
            </Typography>
            {recepient && (
              <Chip size="sm" variant="soft" color="primary" onClick={() => {}}>
                {recepient}
              </Chip>
            )}
          </Box>
        </Box>
      </ListItemButton>
    </ListItem>
  );
}
