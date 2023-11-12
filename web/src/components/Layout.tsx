import * as React from "react";
import Box, { BoxProps } from "@mui/joy/Box";
import Sheet from "@mui/joy/Sheet";

type RootProps = BoxProps & {
  cols: number;
};

function Root(props: RootProps) {
  let gridTemplateColumns;
  switch (props.cols) {
    case 1: {
      gridTemplateColumns = {
        xs: "1fr",
        sm: "1fr",
        md: "1fr",
      };
      break;
    }
    case 2: {
      gridTemplateColumns = {
        xs: "1fr",
        sm: "minmax(64px, 200px) minmax(450px, 1fr)",
        md: `minmax(160px, 300px) minmax(500px, 1fr)`,
      };
      break;
    }
    case 3: {
      gridTemplateColumns = {
        xs: "1fr",
        sm: "minmax(64px, 200px) minmax(450px, 1fr)",
        md: `minmax(160px, 300px) minmax(300px, 500px) minmax(500px, 1fr)`,
      };
      break;
    }
  }

  return (
    <Box
      {...props}
      sx={[
        {
          display: "grid",
          gridTemplateColumns,
          gridTemplateRows: "64px 1fr",
          minHeight: "100vh",
          maxHeight: "100vh",
        },
        ...(Array.isArray(props.sx) ? props.sx : [props.sx]),
      ]}
    />
  );
}

function Header(props: BoxProps) {
  return (
    <Box
      component="header"
      className="Header"
      {...props}
      sx={[
        {
          p: 2,
          gap: 2,
          bgcolor: "background.surface",
          display: "flex",
          flexDirection: "row",
          justifyContent: "space-between",
          alignItems: "center",
          gridColumn: "1 / -1",
          borderBottom: "1px solid",
          borderColor: "divider",
          position: "sticky",
          top: 0,
          zIndex: 1100,
        },
        ...(Array.isArray(props.sx) ? props.sx : [props.sx]),
      ]}
    />
  );
}

type SideNavProps = BoxProps & {
  main?: boolean;
};

function SideNav(props: SideNavProps) {
  return (
    <Box
      component="nav"
      className="Navigation"
      {...props}
      sx={[
        {
          p: 2,
          ...(!props.main && {
            bgcolor: "background.surface",
            borderRight: "1px solid",
            borderColor: "divider",
            display: {
              xs: "none",
              sm: "initial",
            },
          }),
        },
        ...(Array.isArray(props.sx) ? props.sx : [props.sx]),
      ]}
    />
  );
}

function SidePane(props: BoxProps) {
  return (
    <Box
      className="Inbox"
      {...props}
      sx={[
        {
          bgcolor: "background.surface",
          borderRight: "1px solid",
          borderColor: "divider",
          display: {
            xs: "none",
            md: "initial",
          },
          overflow: {
            xs: "initial",
            sm: "auto",
          },
        },
        ...(Array.isArray(props.sx) ? props.sx : [props.sx]),
      ]}
    />
  );
}

function Main(props: BoxProps) {
  return (
    <Box
      component="main"
      className="Main"
      {...props}
      sx={[
        {
          p: 2,
          overflow: {
            xs: "initial",
            sm: "auto",
          },
        },
        ...(Array.isArray(props.sx) ? props.sx : [props.sx]),
      ]}
    />
  );
}

function SideDrawer({
  onClose,
  ...props
}: BoxProps & { onClose: React.MouseEventHandler<HTMLDivElement> }) {
  return (
    <Box
      {...props}
      sx={[
        { position: "fixed", zIndex: 1200, width: "100%", height: "100%" },
        ...(Array.isArray(props.sx) ? props.sx : [props.sx]),
      ]}
    >
      <Box
        role="button"
        onClick={onClose}
        sx={{
          position: "absolute",
          inset: 0,
          bgcolor: (theme) =>
            `rgba(${theme.vars.palette.neutral.darkChannel} / 0.8)`,
        }}
      />
      <Sheet
        sx={{
          minWidth: 256,
          width: "max-content",
          height: "100%",
          p: 2,
          boxShadow: "lg",
          bgcolor: "background.surface",
        }}
      >
        {props.children}
      </Sheet>
    </Box>
  );
}

export default {
  Root,
  Header,
  SideNav,
  SidePane,
  SideDrawer,
  Main,
};
