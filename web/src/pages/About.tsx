import Box from "@mui/joy/Box";
import Typography from "@mui/joy/Typography";

import Logo from "../../assets/logo.svg";

// custom
import Layout from "../components/Layout";
import Header from "../components/Header";

import { Link as RouterLink } from "react-router-dom";

import { AspectRatio, Container, Link } from "@mui/joy";
import { useAuth } from "../auth";
import { useTitle } from "../components/useTitle";

export default function About() {
  const { auth } = useAuth();

  useTitle("About");

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
              justifyContent: "flex-start",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 2,
              py: 1,
            }}
          >
            <AspectRatio ratio="1" sx={{ minWidth: 60 }} variant="plain">
              <img src={Logo} alt="Compost Mail" />
            </AspectRatio>
            <Typography level="h2">Compost Mail</Typography>
          </Box>
          <Box>
            <Typography level="body-md" sx={{ py: 1 }}>
              Compost Mail is a no-frills open-source webmail service for your
              domains. It requires no registration, instead it uses public-key
              cryptography for authentication and privacy.
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              It is geared towards developers who need to test email flows in
              their applications, but don't want to use their personal email
              addresses.
            </Typography>
            <Typography level="h3" sx={{ py: 1 }}>
              Quickstart
            </Typography>
            <ol>
              <li>
                {auth && (
                  <>
                    Click <strong>Add Domain</strong> in{" "}
                    <Link component={RouterLink} to="/domains">
                      Domains
                    </Link>
                  </>
                )}

                {!auth && (
                  <>
                    Go to{" "}
                    <Link component={RouterLink} to="/domains">
                      Domains
                    </Link>
                  </>
                )}
              </li>
              <li>Enter a domain (can be a subdomain) that you control</li>
              <li>
                Select a secure mnemonic phrase. This is used to generate a
                public/private key pair.
              </li>
              <li>
                You will be prompted to add a MX and a TXT record to your
                domain's DNS. The TXT record is the generated public key.
              </li>
              <li>
                That's it! You can now see incoming emails for any address at
                that domain.
              </li>
            </ol>
            <Typography level="h3" sx={{ py: 1 }}>
              How it works
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              When Compost receives an email, it looks up the TXT record for the
              domain in the email address. If the public key in the TXT is a
              valid public key, it considers itself authorized to receive email
              for that domain. The public key is used to encrypt the email, so
              that only the owner of the private key can decrypt it.
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              Decryption happens in your browser, so the private key never
              leaves your device.
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              The public key is also used for API authentication. All the
              requests to the API contain a JSON Web Token (JWT) that is signed
              with the private key. Once the API receives the request, it
              verifies the JWT using the public key from DNS.
            </Typography>
            <Typography level="body-md" sx={{ pt: 1 }}>
              There is no state stored on the server apart from the emails
              themselves (email bodies, metadata and indexes). The following
              identifying information is not encrypted, but merely hashed:
            </Typography>
            <ul>
              <li>Domain name itself</li>
              <li>Email addresses of all the recepient</li>
            </ul>
            <Typography level="body-md" sx={{ pb: 1 }}>
              Salt can be chosen by the user and put into the TXT record. This
              provides some degree of privacy even if our database is
              compromised, as there is no easy way to link the hashed
              identifiers back to the domain.
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              If the key is changed in DNS, the emails still stay on the server
              and can be decrypted with the old key. Compost client will offer
              to keep the old key in the browser for decryption only. This is
              useful if you want to rotate your keys, but don't want to lose
              access to the old emails.
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}></Typography>
            <Typography level="h3" sx={{ py: 1 }}>
              Limitations
            </Typography>
            <Typography level="body-md" sx={{ pt: 1 }}>
              Compared to a traditional email service, Compost has the following
              limitations:
            </Typography>
            <ul>
              <li>
                Can only receive emails, as operating what is essentially a open
                relay is too risky. You are of course free to use another relay
                to send emails.
              </li>
              <li>Email bodies are limited to 25MB</li>
              <li>Emails are deleted after 30 days</li>
              <li>
                No separate user accounts - whoever has the private key can
                access the emails for the entire domain
              </li>
              <li>
                No anti-spam measures. SPF/DKIM/DMARC support is planned, but it
                will be opt-in.
              </li>
            </ul>
            <Typography level="h3" sx={{ py: 1 }}>
              Technical details
            </Typography>
            <Typography level="h4" sx={{ py: 1 }}>
              Architecture
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              Frontend is a single-page application written in TypeScript using
              React and Mui Joy UI toolkit. It uses IndexedDB for key storage.
              The backend is a combined SMTP and HTTP server written in Rust
              (Axum framework). It uses S3 for both email and metadata storage
              and does not require a database.
            </Typography>
            <Typography level="h4" sx={{ py: 1 }}>
              Cryptography
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              Elliptic curve cryptography is used for both email encryption and
              authentication of API requests. The curve used is NIST P-256. The
              public key is stored in the TXT record as a base64-encoded
              DER-encoded ASN.1 structure (
              <Typography component="code">SubjectPublicKeyInfo</Typography>).
              The private key is stored as a non-extractable{" "}
              <code>CryptoKey</code> in the browser.
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              Private key derivation from a mnemonic phrase is done using 65536
              rounds of PBKDF2-SHA256 with a fixed salt <code>compostmail</code>
              . The 32 bytes of the derived key are used as the seed for
              ChaCha20 CSPRNG, which is then used to generate the private key
              using rejection sampling.
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              JWT tokens are short-lived (60s) as they are generated afresh for
              every API call. They are signed using ECDSA with SHA256 (ES256
              algorithm).
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              Emails and metadata are encrypted using ECIES (hybrid encryption).
              Specifically, using AES-256-GCM for symmetric encryption and
              HKDF-SHA256 to derive the symmetric key from the Diffie-Hellman
              shared secret. The shared secret is generated using ECDH using an
              ephemeral key pair. Ephemeral public key and AES nonce are
              prepended to the ciphertext.
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              Most cryptographic operations are performed in a WebAssembly
              module compiled from Rust. The exception is anything that requires
              access to the private key after initial generation. These are done
              in the browser using{" "}
              <Link href="https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto">
                <code>SubtleCrypto</code>
              </Link>{" "}
              to avoid the need for the private key to be extractable.
            </Typography>
            <Typography level="h4" sx={{ py: 1 }}>
              Source code
            </Typography>
            <Typography level="body-md" sx={{ py: 1 }}>
              The source code is available on{" "}
              <Link href="https://github.com/tibordp/compost">GitHub</Link>.
              Contributions are welcome! It is licensed under the{" "}
              <Link href="https://www.gnu.org/licenses/agpl-3.0.en.html">
                GNU Affero General Public Licence (AGPL-3.0).
              </Link>{" "}
              The SMTP server implementation is adapted from{" "}
              <Link href="https://github.com/stalwartlabs/mail-server">
                Stalwart Mail Server
              </Link>{" "}
              by <Link href="https://stalw.art">Stalwart Labs</Link>, which is
              likewise licensed under AGPL-3.0. If you would like to self-host
              your email properly, I can highly recommend you check out their
              product.
            </Typography>
          </Box>
        </Container>
      </Layout.Main>
    </Layout.Root>
  );
}
