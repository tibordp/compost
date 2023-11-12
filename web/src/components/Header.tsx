import * as React from "react";
import Box from "@mui/joy/Box";
import IconButton from "@mui/joy/IconButton";
import Stack from "@mui/joy/Stack";
import Avatar from "@mui/joy/Avatar";
import Dropdown from "@mui/joy/Dropdown";
import Menu from "@mui/joy/Menu";
import MenuButton from "@mui/joy/MenuButton";
import MenuItem from "@mui/joy/MenuItem";
import ListDivider from "@mui/joy/ListDivider";
import Drawer from "@mui/joy/Drawer";
import ModalClose from "@mui/joy/ModalClose";
import DialogTitle from "@mui/joy/DialogTitle";

import Logo from "../../assets/logo.svg";

import DomainIcon from "@mui/icons-material/Domain";
import InfoIcon from "@mui/icons-material/Info";
import MenuRoundedIcon from "@mui/icons-material/MenuRounded";

// Custom
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth";
import { Typography } from "@mui/joy";

type HeaderProps = {
  navigation?: React.ReactNode;
};

export default function Header({ navigation }: HeaderProps) {
  const [open, setOpen] = React.useState(false);

  const { auth, domains, setActiveDomain } = useAuth();

  const location = useLocation();
  const navigate = useNavigate();

  React.useEffect(() => {
    setOpen(false);
  }, [location]);

  return (
    <Box
      sx={{
        display: "flex",
        flexGrow: 1,
        justifyContent: "space-between",
      }}
    >
      <Stack
        direction="row"
        justifyContent="center"
        alignItems="center"
        spacing={1}
        sx={{ display: navigation ? { xs: "none", sm: "flex" } : "flex" }}
      >
        <IconButton
          size="lg"
          color="neutral"
          variant="plain"
          component={Link}
          to={auth ? "/" : "/about"}
          sx={{
            display: navigation
              ? { xs: "none", sm: "inline-flex" }
              : "inline-flex",
            borderRadius: "50%",
          }}
        >
          <img src={Logo} alt="Logo" />
        </IconButton>
      </Stack>
      <Box sx={{ display: { xs: "inline-flex", sm: "none" } }}>
        {navigation && (
          <>
            <IconButton
              variant="plain"
              color="neutral"
              onClick={() => setOpen(true)}
            >
              <MenuRoundedIcon />
            </IconButton>
            <Drawer
              sx={{ display: { xs: "inline-flex", sm: "none" } }}
              open={open}
              onClose={() => setOpen(false)}
            >
              <ModalClose />
              <DialogTitle>Compost</DialogTitle>
              <Box sx={{ px: 1 }}>{navigation}</Box>
            </Drawer>
          </>
        )}
      </Box>

      <Box
        sx={{
          display: "flex",
          flexDirection: "row",
          gap: 1.5,
          alignItems: "center",
        }}
      >
        <Dropdown>
          <MenuButton
            variant="plain"
            component={auth ? Box : "button"}
            size="sm"
            sx={{
              display: "flex",
              flexDirection: "row",
              gap: 1,
              ...(!auth
                ? {
                    maxWidth: "32px",
                    maxHeight: "32px",
                    borderRadius: "9999999px",
                  }
                : {}),
            }}
          >
            <Avatar children={<DomainIcon />} />
            {auth && (
              <Box sx={{ flex: 1, maxWidth: 150 }}>
                <Typography
                  sx={{
                    minWidth: 0,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    wordWrap: "break-word",
                  }}
                  level="title-sm"
                >
                  {auth.domain}
                </Typography>
              </Box>
            )}
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
            {domains && domains.length > 0 && (
              <>
                {domains.map((domain) => (
                  <MenuItem
                    key={domain.name}
                    disabled={domain.name === auth?.domain}
                    onClick={() => {
                      setActiveDomain(domain.name).then(() => navigate("/"));
                    }}
                  >
                    {domain.name}
                    {domain.name === auth?.domain ? " (active)" : ""}
                  </MenuItem>
                ))}
                <ListDivider />
              </>
            )}
            <MenuItem component={Link} to="/domains">
              <DomainIcon />
              Domains
            </MenuItem>
            <ListDivider />
            <MenuItem component={Link} to="/about">
              <InfoIcon />
              About
            </MenuItem>
          </Menu>
        </Dropdown>
      </Box>
    </Box>
  );
}
