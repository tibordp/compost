import Box from "@mui/joy/Box";
import Typography from "@mui/joy/Typography";

// custom
import Layout from "../components/Layout";
import Header from "../components/Header";

import { Link as RouterLink } from "react-router-dom";

import { Container, Link } from "@mui/joy";
import { useTitle } from "../components/useTitle";

export default function NotFound() {
  useTitle("Not Found");

  return (
    <Layout.Root cols={1}>
      <Layout.Header>
        <Header />
      </Layout.Header>

      <Layout.Main sx={{ px: 0 }}>
        <Container>
          <Box
            sx={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 2,
              py: 1,
            }}
          >
            <Typography level="h2">Not Found</Typography>
          </Box>
          <Box>
            <Typography level="body-md">
              <p>
                The page you are looking for does not exist. It may have been
                moved, or removed altogether. Perhaps you can return back to the
                site's homepage and see if you can find what you are looking
                for. Or perhaps you are exactly where you want to be. We hope
                you find what you are looking for.
              </p>
              <p>
                <Link component={RouterLink} to="/">
                  Go to homepage
                </Link>
              </p>
            </Typography>
          </Box>
        </Container>
      </Layout.Main>
    </Layout.Root>
  );
}
