import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto from "node:crypto";
import { ethers } from "ethers";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import { prefixWith0x } from "../../src/utils/index.js";
import { Client } from "../../src/utils/Client.js";
import { randomOid } from "../../src/buildParam/index.js";
import { PaginatedList } from "../../src/interfaces/index.js";
import { consoleOutput } from "../utils/utils.js";
import { generateTokenWebAppOnboarding } from "../utils/onboarding.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, admin, requesterApp } = config.vitest;
let newUser: Client;
let didDocument1: string;
let didDocument2: string;

describe("DID Registry Old V3 (e2e)", () => {
  let totalHashAlgorithms: number;

  beforeAll(async () => {
    if (writeOpsEnabled) {
      if (!config.besuProvider) {
        // oauth2 session to access ledger api
        await execCommand(
          `using app ${requesterApp.name} ${requesterApp.privateKey}`
        );
        await execCommand("tokenLedger: authorisation-old oauth2 ledger-api");
        await execCommand("using oauth2token tokenLedger");
      }

      // siop session for the admin
      await execCommand(
        `using user ES256K did1 ${admin.privateKey} ${admin.did} ${admin.keyId}`
      );
      await execCommand("tokenAdmin: authorisation-old siop");

      const response = await execCommand<{
        total: number;
      }>("did-old get /hash-algorithms");

      totalHashAlgorithms = response.total;
    }

    // siop session for the user
    await execCommand("using user null");
    await execCommand(
      `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
    );
    await execCommand("tokenUser: authorisation-old siop");

    // siop session for a new user
    const tokenCaptcha = await generateTokenWebAppOnboarding();
    await execCommand("using user null");
    newUser = await execCommand("using user ES256K did1");
    await execCommand(`using token ${tokenCaptcha}`);
    await execCommand(`tokenNewUser: onboarding authentication`);

    didDocument1 = JSON.stringify(newUser.generateDidDocument());

    newUser = await execCommand("using user ES256 did1");
    didDocument2 = JSON.stringify(newUser.generateDidDocument());
  });

  describe("GET /identifiers", () => {
    const controller = new ethers.Wallet(prefixWith0x(user1.privateKey))
      .address;
    let versionId: string;
    let metadataId: string;

    it("should get a collection of identifiers", async () => {
      expect.assertions(1);
      const result = await execCommand("did-old get /identifiers");
      expect(result).toStrictEqual({
        self: expect.any(String) as string,
        items: expect.arrayContaining([]) as unknown[],
        total: expect.any(Number) as number,
        pageSize: expect.any(Number) as number,
        links: {
          first: expect.any(String) as string,
          prev: expect.any(String) as string,
          next: expect.any(String) as string,
          last: expect.any(String) as string,
        },
      });
    });

    it("should get a collection of identifiers filtered by controller", async () => {
      expect.assertions(2);
      const result = await execCommand<PaginatedList>(
        `did-old get /identifiers?controller=${controller}`
      );
      expect(result).toStrictEqual({
        self: expect.any(String) as string,
        items: expect.arrayContaining([]) as unknown[],
        total: expect.any(Number) as number,
        pageSize: expect.any(Number) as number,
        links: {
          first: expect.any(String) as string,
          prev: expect.any(String) as string,
          next: expect.any(String) as string,
          last: expect.any(String) as string,
        },
      });
      expect(result.items.length > 0).toBeTruthy();
    });

    it("should get a did", async () => {
      expect.assertions(1);
      await expect(
        execCommand(`did-old get /identifiers/${user1.did}`)
      ).resolves.toBeDefined();
    });

    it("should get the versions of a did", async () => {
      expect.assertions(1);
      const result = await execCommand<
        PaginatedList<{
          versionId: string;
          href: string;
        }>
      >(`did-old get /identifiers/${user1.did}/versions`);
      expect(result).toStrictEqual({
        self: expect.any(String) as string,
        items: expect.arrayContaining([]) as unknown[],
        total: expect.any(Number) as number,
        pageSize: expect.any(Number) as number,
        links: {
          first: expect.any(String) as string,
          prev: expect.any(String) as string,
          next: expect.any(String) as string,
          last: expect.any(String) as string,
        },
      });
      versionId = result.items[0].versionId;
    });

    it("should resolve a did by its version id", async () => {
      expect.assertions(1);
      await expect(
        execCommand(
          `did-old get /identifiers/${user1.did}/versions/${versionId}`
        )
      ).resolves.toBeDefined();
    });

    it("should get metadata collection from a revision from a did", async () => {
      expect.assertions(1);
      const data = await execCommand<
        PaginatedList<{
          metadataId: string;
          href: string;
        }>
      >(`did-old get /identifiers/${user1.did}/versions/${versionId}/metadata`);
      expect(data).toStrictEqual({
        self: expect.any(String) as string,
        items: expect.arrayContaining([]) as unknown[],
        total: expect.any(Number) as number,
        pageSize: expect.any(Number) as number,
        links: {
          first: expect.any(String) as string,
          prev: expect.any(String) as string,
          next: expect.any(String) as string,
          last: expect.any(String) as string,
        },
      });
      metadataId = data.items[0].metadataId;
    });

    it("should get the metadata content from a revision from a did", async () => {
      expect.assertions(1);
      await expect(
        execCommand(
          `did-old get /identifiers/${user1.did}/versions/${versionId}/metadata/${metadataId}`
        )
      ).resolves.toBeDefined();
    });
  });

  describe("GET /did-timestamps", () => {
    let timestampId: string;

    it("should get a collection of did-timestamps", async () => {
      expect.assertions(1);
      const data = await execCommand<
        PaginatedList<{
          timestampId: string;
          href: string;
        }>
      >("did-old get /did-timestamps");
      expect(data.items.length > 0).toBeTruthy();
      timestampId = data.items[0].timestampId;
    });

    it("should get a did-timestamp filtered by did and version-id", async () => {
      expect.assertions(1);
      await expect(
        execCommand(
          `did-old get /did-timestamps?identifier=${user1.did}&version-id=1`
        )
      ).resolves.toBeDefined();
    });

    it("should get a did-timestamp", async () => {
      expect.assertions(1);
      await expect(
        execCommand(`did-old get /did-timestamps/${timestampId}`)
      ).resolves.toBeDefined();
    });
  });

  describe("GET /hash-algorithms", () => {
    it("should get a collection of hash-algorithms", async () => {
      expect.assertions(1);
      await expect(
        execCommand("did-old get /hash-algorithms")
      ).resolves.toBeDefined();
    });

    it("should get a hash-algorithm", async () => {
      expect.assertions(1);
      await expect(
        execCommand(`did-old get /hash-algorithms/1`)
      ).resolves.toBeDefined();
    });
  });

  describeWriteOps("POST /jsonrpc", () => {
    const hashAlg = {
      id: -1,
      outputLength: 256,
      ianaName: `test-${crypto.randomBytes(12).toString("hex")}`,
      oid: randomOid(),
      status: 1,
      multihash: "sha2-256",
    };

    const timestamp2 = { test: crypto.randomBytes(32).toString("hex") };
    const metadata2 = { test: crypto.randomBytes(32).toString("hex") };
    const newController = ethers.Wallet.createRandom().address;
    // const policyId = `policy-${crypto.randomBytes(10).toString("hex")}`;

    const commandsAdmin = [
      // insertPolicy and updatePolicy are not protected
      // ["insertPolicy", () => policyId],
      // ["updatePolicy", () => policyId],
      [
        "insertHashAlgorithm",
        () =>
          `${hashAlg.outputLength} ${hashAlg.ianaName} ${hashAlg.oid} ${hashAlg.status} ${hashAlg.multihash}`,
      ],
      [
        "updateHashAlgorithm",
        () =>
          `${totalHashAlgorithms} ${hashAlg.outputLength} ${hashAlg.ianaName} ${hashAlg.oid} ${hashAlg.status} ${hashAlg.multihash}`,
      ],
    ];

    const commandsUser = [
      ["insertDidDocument", () => `${newUser.did} ${didDocument1}`],
      ["updateDidDocument", () => `${newUser.did} ${didDocument2}`],
      ["insertDidController", () => `${newUser.did} ${newController}`],
      ["revokeDidController", () => `${newUser.did} ${newController}`],
      [
        "appendDidDocumentVersionHash",
        () => `${newUser.did} ${didDocument2} ${JSON.stringify(timestamp2)}`,
      ],
      [
        "appendDidDocumentVersionMetadata",
        () => `${newUser.did} ${didDocument2} ${JSON.stringify(metadata2)}`,
      ],
      [
        "detachDidDocumentVersionMetadata",
        () => `${newUser.did} ${didDocument2} ${JSON.stringify(metadata2)}`,
      ],
      ["detachDidDocumentVersionHash", () => `${newUser.did} ${didDocument2}`],
      ["updateDidController", () => `${newUser.did} ${newController}`],
    ];

    describe.each(commandsAdmin)(
      "Restricted user access when using %s",
      (method: string, params: () => string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
          );
          await execCommand("using token tokenUser");
        });

        it("should reject not an administrator", async () => {
          expect.assertions(1);
          vi.resetAllMocks();

          await expect(
            execCommand(`did-old ${method} ${params()}`)
          ).rejects.toThrow(
            `Policy error: sender doesn't have the attribute DIDR:${method}`
          );
        });
      }
    );

    describe.each(commandsAdmin)(
      "send transaction for %s",
      (method: string, params: () => string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${admin.privateKey} ${admin.did} ${admin.keyId}`
          );
          await execCommand("using token tokenAdmin");
        });

        it("should work", async () => {
          expect.assertions(1);
          await expect(
            execCommand(`did-old ${method} ${params()}`)
          ).resolves.toBeDefined();
        });
      }
    );

    describe.each(commandsUser)(
      "send transaction for %s",
      (method: string, params: () => string) => {
        it("should reject operations to DID documents using a different DID in the JWT", async () => {
          expect.assertions(2);
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
          );
          await execCommand("using token tokenUser");

          vi.resetAllMocks();

          await expect(
            execCommand(`did-old ${method} ${params()}`)
          ).rejects.toThrow();

          const error = consoleOutput(mockConsole, -1);

          expect(error).toStrictEqual({
            jsonrpc: "2.0",
            error: {
              code: -32600,
              message: `Identifier ${newUser.did} doesn't match JWT's DID ${user1.did}`,
            },
            id: expect.any(Number) as number,
          });
        });

        it("should work", async () => {
          expect.assertions(1);
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${newUser.ethWallet.privateKey.slice(2)} ${
              newUser.did
            } ${newUser.keys.ES256K.id}`
          );
          await execCommand("using token tokenNewUser");
          await expect(
            execCommand(`did-old ${method} ${params()}`)
          ).resolves.toBeDefined();
        });
      }
    );
  });
});
