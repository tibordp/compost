let db: IDBDatabase | null = null;

const openDb = async (): Promise<IDBDatabase> => {
  if (db) {
    return db;
  }

  db = await new Promise((resolve, reject) => {
    const request = indexedDB.open("compost", 3);
    request.onerror = (event) => {
      reject(event);
    };
    request.onsuccess = (event) => {
      resolve((event.target as any).result);
    };
    request.onupgradeneeded = (event) => {
      const db = (event.target as any).result as IDBDatabase;
      if (!db.objectStoreNames.contains("domains")) {
        db.createObjectStore("domains", { keyPath: "name" });
      }
      if (!db.objectStoreNames.contains("passiveKeys")) {
        db.createObjectStore("passiveKeys", { keyPath: "publicKey" });
      }
    };
  });

  return db!;
};

export type PassiveKey = {
  originalDomain: string;
  publicKey: string;
  privateKey: CryptoKey;
};

export type Domain = {
  name: string;
  signingKey: CryptoKey;
  encryptionKey: CryptoKey;
  publicKey: string;
  salt: string;
};

export const getDomains = async (): Promise<Domain[]> => {
  const db = await openDb();
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(["domains"]);
    tx.onerror = () => reject(tx.error);
    const objectStore = tx.objectStore("domains");
    const request = objectStore.getAll();
    request.onsuccess = () => resolve(request.result);
  });
};

export const getPassiveKeys = async (): Promise<PassiveKey[]> => {
  const db = await openDb();
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(["passiveKeys"]);
    tx.onerror = () => reject(tx.error);
    const objectStore = tx.objectStore("passiveKeys");
    const request = objectStore.getAll();
    request.onsuccess = () => resolve(request.result);
  });
};

export const addDomain = async (domain: Domain): Promise<void> => {
  const db = await openDb();
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(["domains"], "readwrite");
    tx.onerror = () => reject(tx.error);
    tx.oncomplete = () => resolve();

    const objectStore = tx.objectStore("domains");
    objectStore.add(domain);
  });
};

export const passivizeDomain = async (domain: string): Promise<void> => {
  const db = await openDb();
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(["domains", "passiveKeys"], "readwrite");
    tx.onerror = () => reject(tx.error);
    tx.oncomplete = () => resolve();

    const objectStore = tx.objectStore("domains");
    const req1 = objectStore.get(domain);
    req1.onsuccess = () => {
      const domain = req1.result;
      if (!domain) {
        return;
      }

      objectStore.delete(domain.name);
      tx.objectStore("passiveKeys").put({
        originalDomain: domain.name,
        publicKey: domain.publicKey,
        privateKey: domain.encryptionKey,
      });
    };
  });
};

export const removeDomain = async (domain: string): Promise<void> => {
  const db = await openDb();
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(["domains"], "readwrite");
    tx.onerror = () => reject(tx.error);
    tx.oncomplete = () => resolve();

    const objectStore = tx.objectStore("domains");
    objectStore.delete(domain);
  });
};

export const removePassiveKey = async (publicKey: string): Promise<void> => {
  const db = await openDb();
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(["passiveKeys"], "readwrite");
    tx.onerror = () => reject(tx.error);
    tx.oncomplete = () => resolve();

    const objectStore = tx.objectStore("passiveKeys");
    objectStore.delete(publicKey);
  });
};

export const clearAll = async (): Promise<void> => {
  const db = await openDb();
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(["domains", "passiveKeys"], "readwrite");
    tx.onerror = () => reject(tx.error);
    tx.oncomplete = () => resolve();

    tx.objectStore("domains").clear();
    tx.objectStore("passiveKeys").clear();
  });
};
