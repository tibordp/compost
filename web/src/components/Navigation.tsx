import ListItemDecorator from "@mui/joy/ListItemDecorator";

import List from "@mui/joy/List";
import ListItem from "@mui/joy/ListItem";
import ListItemButton from "@mui/joy/ListItemButton";
import ListItemContent from "@mui/joy/ListItemContent";
import Typography from "@mui/joy/Typography";
import EmailIcon from "@mui/icons-material/Email";

// Icons import
import InboxRoundedIcon from "@mui/icons-material/InboxRounded";
import LockOutlinedIcon from "@mui/icons-material/LockOutlined";
import { Link } from "react-router-dom";
import { useAccounts } from "../query";
import { Box, LinearProgress } from "@mui/joy";

type NavigationProps = {
  account?: string;
};

export default function Navigation({ account }: NavigationProps) {
  const { isPending, error, data } = useAccounts();

  return (
    <List
      size="sm"
      sx={{
        "--List-nestedInsetStart": "10px",
        "--ListItem-radius": "8px",
        "--List-gap": "4px",
      }}
    >
      <ListItem nested>
        <ListItemButton component={Link} to="/" selected={!account}>
          <EmailIcon />
          <ListItemContent>
            <Typography level="title-sm">All accounts</Typography>
          </ListItemContent>
        </ListItemButton>
        <Box
          sx={{
            display: "grid",
            gridTemplateRows: "1fr",
            transition: "0.2s ease",
            "& > *": {
              overflow: "hidden",
            },
          }}
        >
          <List aria-labelledby="nav-list-browse">
            {(isPending || error || data?.length === 0) && (
              <ListItem>
                {isPending && <LinearProgress />}
                {error && !isPending && <>Could not load accounts</>}
                {!isPending && !error && data?.length === 0 && (
                  <>No accounts found</>
                )}
              </ListItem>
            )}
            {data?.map(({ id, email }) => (
              <ListItem key={id}>
                <ListItemButton
                  component={Link}
                  selected={id === account}
                  to={`/mail/${id}`}
                >
                  <ListItemDecorator>
                    {!email ? (
                      <LockOutlinedIcon fontSize="small" />
                    ) : (
                      <InboxRoundedIcon fontSize="small" />
                    )}
                  </ListItemDecorator>
                  <ListItemContent
                    sx={{ textOverflow: "ellipsis", overflow: "hidden" }}
                  >
                    {!email ? "Could not decrypt" : email}
                  </ListItemContent>
                </ListItemButton>
              </ListItem>
            ))}
          </List>
        </Box>
      </ListItem>
    </List>
  );
}
