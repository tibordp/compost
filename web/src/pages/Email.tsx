import * as React from "react";

import Layout from "../components/Layout";
import Navigation from "../components/Navigation";
import EmailList from "../components/EmailList";
import EmailContent from "../components/EmailContent";
import Header from "../components/Header";
import { useNavigate, useParams } from "react-router";
import { useAuth } from "../auth";
import { useTitle } from "../components/useTitle";

export default function Mail() {
  const { account, email } = useParams();
  const { auth } = useAuth();
  const navigate = useNavigate();

  useTitle(auth?.domain);

  React.useEffect(() => {
    if (!auth) {
      navigate("/about", { replace: true });
    }
  }, [auth]);

  return (
    <Layout.Root cols={email ? 3 : 2}>
      <Layout.Header>
        <Header navigation={<Navigation account={account} />} />
      </Layout.Header>
      <Layout.SideNav>
        <Navigation account={account} />
      </Layout.SideNav>
      <Layout.SidePane
        sx={
          email
            ? {}
            : {
                display: {
                  xs: "initial",
                  md: "initial",
                  lg: "initial",
                },
              }
        }
      >
        <EmailList account={account} email={email} />
      </Layout.SidePane>
      {email && account && (
        <Layout.Main>
          <EmailContent account={account} email={email} />
        </Layout.Main>
      )}
    </Layout.Root>
  );
}
