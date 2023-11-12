import { useQueries, useQuery } from "@tanstack/react-query";
import { Auth, useAuth } from "./auth";

export type Account = {
  id: string;
  email: string;
};

async function fetchAccounts(auth: Auth) {
  if (!auth) {
    throw new Error("Not authenticated");
  }

  const token = await auth.getToken();
  const response = await fetch("/api/v1/directory", {
    method: "GET",
    headers: new Headers({
      Authorization: `Bearer ${token}`,
    }),
  });
  if (!response.ok) {
    // Throw an error if the response status code is not in the 200-299 range
    throw new Error(`Request failed with status ${response.status}`);
  }
  const data = await response.json();

  const accounts = await Promise.all(
    data.map(async (item: any) => {
      let decrypted;
      try {
        decrypted = await auth.decryptString(item.email_encrypted);
      } catch (e) {}

      return {
        id: item.id,
        email: decrypted,
      };
    })
  );

  return accounts.sort((a, b) => (a.email ?? "").localeCompare(b.email ?? ""));
}

export const useAccounts = (): Result<Account[]> => {
  const { auth } = useAuth();

  return useQuery({
    enabled: !!auth,
    queryKey: [auth?.domain, "directory"],
    queryFn: async () => {
      return await fetchAccounts(auth!);
    },
  });
};

export type Address = {
  name: string;
  address: string;
};

export type InboxEntryMetadata = {
  from: Address[];
  subject?: string;
  datetime: string;
};

export type InboxEntry = {
  account_id: string;
  id: string;
  blob_url: string;
  metadata?: InboxEntryMetadata;
};

export interface Result<T> {
  data?: T;
  isPending: boolean;
  error: Error | null;
}

export const useEmailList = (account?: string): Result<InboxEntry[]> => {
  const { auth } = useAuth();

  const accounts = useAccounts();
  const accountIds =
    (account ? [account] : accounts.data?.map((a) => a.id)) || [];

  return useQueries({
    queries: accountIds.map((id) => ({
      queryKey: [auth?.domain, "inbox", id],
      queryFn: async () => {
        return await fetchEmailList(auth!, id);
      },
    })),
    combine: (results) => {
      return {
        data: results
          .filter((result) => result.data)
          .flatMap((result) => result.data!)
          .sort((a, b) => a.id.localeCompare(b.id)),
        isPending: results.some((result) => result.isPending),
        error: results.find((result) => result.error)?.error || null,
      };
    },
  });
};

export type Email = {
  body?: string;
};

const decryptionFailed = Symbol();
export const useBlob = (account: string, message: string): Result<string> => {
  const { auth } = useAuth();

  const { data, isPending, error } = useQuery({
    queryKey: [auth?.domain, "blob", account, message],
    queryFn: async () => {
      if (!auth) {
        throw new Error("Not authenticated");
      }

      const token = await auth.getToken();
      const response = await fetch(`/api/v1/inbox/${account}/blob/${message}`, {
        method: "GET",
        headers: new Headers({
          Authorization: `Bearer ${token}`,
        }),
      });
      if (!response.ok) {
        // Throw an error if the response status code is not in the 200-299 range
        throw new Error(`Request failed with status ${response.status}`);
      }

      try {
        return await auth.decrypt(new Uint8Array(await response.arrayBuffer()));
      } catch (e) {
        // TODO: this is to prevent Tanstack from retrying the request
        // when the decryption fails. It's ugly, please fix it.
        return decryptionFailed;
      }
    },
  });

  return data === decryptionFailed
    ? {
        isPending,
        error: new Error("Could not decrypt"),
      }
    : {
        data,
        isPending,
        error,
      };
};

async function fetchEmailList(
  auth: Auth,
  account: string
): Promise<InboxEntry[]> {
  if (!auth) {
    throw new Error("Not authenticated");
  }

  const token = await auth.getToken();
  const response = await fetch(`/api/v1/inbox/${account}?limit=500`, {
    method: "GET",
    headers: new Headers({
      Authorization: `Bearer ${token}`,
    }),
  });
  if (!response.ok) {
    // Throw an error if the response status code is not in the 200-299 range
    throw new Error(`Request failed with status ${response.status}`);
  }
  const data = await response.json();

  return await Promise.all(
    data.map(async (item: any) => {
      let decrypted;
      try {
        decrypted = JSON.parse(
          await auth.decryptString(item.metadata_encrypted)
        );
      } catch (e) {}

      return {
        account_id: account,
        id: item.id,
        blob_url: item.blob_url,
        metadata: decrypted,
      };
    })
  );
}
