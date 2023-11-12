import {
  decrypt_fom_dh,
  EncryptedPayload,
  public_key_to_der,
  derive_private_key,
} from "compost_crypto";
import React from "react";
import {
  Domain,
  PassiveKey,
  addDomain,
  getDomains,
  getPassiveKeys,
  passivizeDomain,
  removeDomain,
  removePassiveKey,
} from "./keystore";

export const decodeBase64 = (encoded: string): Uint8Array => {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

export const decodeBase64Url = (encoded: string): Uint8Array => {
  return decodeBase64(encoded.replace(/-/g, "+").replace(/_/g, "/"));
};

export const encodeBase64 = (input: Uint8Array | string): string => {
  let unencoded = input;
  if (typeof unencoded === "string") {
    unencoded = new TextEncoder().encode(unencoded);
  }
  const CHUNK_SIZE = 0x8000;
  const arr = [];
  for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
    arr.push(
      // @ts-expect-error
      String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE))
    );
  }
  return btoa(arr.join(""));
};

export const encodeBase64Url = (input: Uint8Array | string): string => {
  return encodeBase64(input)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
};

export type Auth = {
  allDomains: Domain[];
  domain: string;
  getToken: () => Promise<string>;
  decrypt: (ciphertext: Uint8Array) => Promise<string>;
  decryptString: (ciphertext: string) => Promise<string>;
};

const decyptWithKey = async (
  key: CryptoKey,
  ciphertext: Uint8Array
): Promise<string> => {
  const encr = EncryptedPayload.from_bytes(ciphertext);
  const ephSpki = public_key_to_der(encr.public_key());
  const pub = await window.crypto.subtle.importKey(
    "spki",
    ephSpki,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    false,
    []
  );
  const agreement = await window.crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: pub,
    },
    key,
    256
  );
  const plaintext = decrypt_fom_dh(new Uint8Array(agreement), encr);
  let utf8decoder = new TextDecoder();
  return utf8decoder.decode(plaintext);
};

export const getAuth = async (): Promise<Auth> => {
  const allDomains = await getDomains();
  if (allDomains.length === 0) {
    window.sessionStorage.removeItem("active_domain");
    throw new Error("No domains configured");
  }

  let activeDomain: Domain;
  let activeDomainName = window.sessionStorage.getItem("active_domain");
  if (!activeDomainName) {
    activeDomain = allDomains[0];
  } else {
    activeDomain =
      allDomains.find((d) => d.name === activeDomainName) || allDomains[0];
  }
  window.sessionStorage.setItem("active_domain", activeDomain.name);

  const getToken = async (): Promise<string> => {
    const header = { alg: "ES256", typ: "JWT", kid: activeDomain.name };
    const payload = {
      sub: activeDomain.name,
      iat: Math.floor(Date.now() / 1000),
      // since we are generating a token for immediate use, we can have very short expiry
      exp: Math.floor(Date.now() / 1000) + 60,
    };
    const head = `${encodeBase64Url(JSON.stringify(header))}.${encodeBase64Url(
      JSON.stringify(payload)
    )}`;
    const signature = await window.crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      activeDomain.signingKey,
      new TextEncoder().encode(head)
    );
    return `${head}.${encodeBase64Url(new Uint8Array(signature))}`;
  };

  const decrypt = async (ciphertext: Uint8Array): Promise<string> => {
    try {
      return await decyptWithKey(activeDomain.encryptionKey, ciphertext);
    } catch (e) {
      let passiveKeys = await getPassiveKeys();
      for (let i = 0; i < passiveKeys.length; i++) {
        try {
          return await decyptWithKey(passiveKeys[i].privateKey, ciphertext);
        } catch (e) {
          continue;
        }
      }
    }
    throw new Error("Could not decrypt");
  };

  const decryptString = async (ciphertext: string): Promise<string> => {
    return decrypt(decodeBase64(ciphertext));
  };

  return {
    allDomains,
    domain: activeDomain["name"],
    getToken,
    decrypt,
    decryptString,
  };
};

type AuthContextType = {
  auth: Auth | null;
  passiveKeys: PassiveKey[];
  setActiveDomain: (domain: string) => Promise<void>;
  domains: Domain[];
  add: (domain: Domain) => Promise<void>;
  remove: (domain: string) => Promise<void>;
  removePassive: (publicKey: string) => Promise<void>;
  passivize: (domain: string) => Promise<void>;
  clearAll: () => Promise<void>;
};

const AuthContext = React.createContext<AuthContextType | null>(null);

type AuthProviderProps = {
  children: React.ReactNode;
  initialAuth: Auth | null;
  initialPassiveKeys: PassiveKey[];
};

export function AuthProvider({
  children,
  initialAuth,
  initialPassiveKeys,
}: AuthProviderProps) {
  const [auth, setAuth] = React.useState<Auth | null>(initialAuth);
  const [passiveKeys, setPassiveKeys] =
    React.useState<PassiveKey[]>(initialPassiveKeys);

  const refreshAuth = async () => {
    getPassiveKeys()
      .then((keys) => {
        setPassiveKeys(keys);
      })
      .catch((e) => console.error(e));

    getAuth()
      .then((auth) => setAuth(auth))
      .catch(() => setAuth(null));
  };

  // Dear Santa, I wish for IndexedDB observers so I can do this properly
  // All writes to the DB must go through this hook, otherwise the UI state
  // may get out of sync (note it still can - if done from another tab)
  const value = React.useMemo(
    () => ({
      auth,
      domains: auth ? auth.allDomains : [],
      passiveKeys,
      setActiveDomain: (domain: string) => {
        window.sessionStorage.setItem("active_domain", domain);
        return getAuth()
          .then((auth) => setAuth(auth))
          .catch(() => setAuth(null));
      },
      add: async (domain: Domain): Promise<void> => {
        await addDomain(domain);
        refreshAuth();
      },
      remove: async (domain: string): Promise<void> => {
        await removeDomain(domain);
        refreshAuth();
      },
      removePassive: async (publicKey: string): Promise<void> => {
        await removePassiveKey(publicKey);
        refreshAuth();
      },
      passivize: async (domain: string): Promise<void> => {
        await passivizeDomain(domain);
        refreshAuth();
      },
      clearAll: async (): Promise<void> => {
        await clearDomains();
        refreshAuth();
      },
    }),
    [auth, passiveKeys]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }

  return context;
};

export async function createDomain(
  domain: string,
  mnemonic: string,
  salt: string
): Promise<Domain> {
  // Todo: UTF-8 normalization
  const asBits = new TextEncoder().encode(mnemonic);
  const der = derive_private_key(asBits);

  return {
    name: domain,
    signingKey: await window.crypto.subtle.importKey(
      "pkcs8",
      der.secret(),
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["sign"]
    ),
    encryptionKey: await window.crypto.subtle.importKey(
      "pkcs8",
      der.secret(),
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      false,
      ["deriveKey", "deriveBits"]
    ),
    publicKey: encodeBase64(der.public()),
    salt,
  };
}
function clearDomains() {
  throw new Error("Function not implemented.");
}
