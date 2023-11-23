import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto from "node:crypto";
import { ethers } from "ethers";
import { loadConfig } from "../../src/config.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import { execCommand } from "../../src/app.js";
import {
  expectCollection,
  expectResponse,
  expectStatus,
} from "../utils/api-get-jest.js";
import {
  expectRevertedTransaction,
  expectTransaction,
} from "../utils/jsonrpc-jest.js";
import { randomOid } from "../../src/buildParam/index.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, admin } = config.vitestNew;

describe("Timestamp (e2e)", () => {
  let totalHashAlgorithms: number;

  beforeAll(async () => {
    if (writeOpsEnabled) {
      // siop session for the admin
      await execCommand(
        `using user ES256K did1 ${admin.privateKey} ${admin.did} ${admin.keyId}`
      );
      await execCommand(
        "tokenAdmin: authorisation-new auth timestamp_write_presentation ES256K"
      );

      // siop session for the user
      await execCommand("using user null");
      await execCommand(
        `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
      );
      await execCommand(
        "tokenUser: authorisation-new auth timestamp_write_presentation ES256K"
      );

      const response = await execCommand<{
        total: number;
      }>("timestamp-new get /hash-algorithms");
      totalHashAlgorithms = response.total;
    }
  });

  describe("GET /hash-algorithms", () => {
    it("should get a collection of hash algorithms", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand("timestamp-new get /hash-algorithms");
      expectCollection(mockConsole);
    });

    it("should get a hash algorithm", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand("timestamp-new get /hash-algorithms/0");
      expectResponse(mockConsole, {
        outputLengthBits: 256,
        ianaName: "sha-256",
        multihash: "sha2-256",
        oid: "2.16.840.1.101.3.4.2.1",
        status: "active",
      });
    });
  });

  describe("GET /timestamps", () => {
    let timestampId: string;
    it("should get a collection of timestamps", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand("timestamp-new get /timestamps");
      const data = expectCollection<{
        timestampId: string;
        href: string;
      }>(mockConsole);
      timestampId = data.items[0].timestampId;
    });

    it("should get a timestamp", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`timestamp-new get /timestamps/${timestampId}`);
      expectResponse(mockConsole, {
        hash: expect.any(String) as string,
        timestampedBy: expect.any(String) as string,
        blockNumber: expect.any(Number) as number,
        timestamp: expect.any(String) as string,
        data: expect.any(String) as string,
        transactionHash: expect.any(String) as string,
      });
    });
  });

  describe("GET /records", () => {
    let recordId: string;
    let versionId: string;
    it("should get a collection of records", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand("timestamp-new get /records");
      const data = expectCollection<{
        recordId: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
      recordId = data.items[0].recordId;
    });

    it("should get a record", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`timestamp-new get /records/${recordId}`);
      expectResponse(
        mockConsole,
        expect.objectContaining({
          ownerIds: expect.arrayContaining([
            expect.any(String) as string,
          ]) as string[],
          revokedOwnerIds: expect.arrayContaining([]) as string[],
          firstVersionTimestamps: expect.arrayContaining([
            expect.any(String) as string,
          ]) as string[],
          lastVersionTimestamps: expect.arrayContaining([
            expect.any(String) as string,
          ]) as string[],
          totalVersions: expect.any(Number) as number,
        })
      );
      expectStatus(mockConsole, 200);
    });

    it("should get the versions of a record", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`timestamp-new get /records/${recordId}/versions`);
      const data = expectCollection<{
        versionId: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
      versionId = data.items[0].versionId;
    });

    it("should resolve a timestamp-new by its version id", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(
        `timestamp-new get /records/${recordId}/versions/${versionId}`
      );
      expectResponse(
        mockConsole,
        expect.objectContaining({
          hashes: expect.arrayContaining([
            expect.any(String) as string,
          ]) as string[],
          info: expect.arrayContaining([
            expect.objectContaining({}),
          ]) as unknown[],
        })
      );
      expectStatus(mockConsole, 200);
    });
  });

  describeWriteOps("POST /jsonrpc", () => {
    const hashAlg = {
      id: null,
      outputLength: 256,
      ianaName: `test-${crypto.randomBytes(12).toString("hex")}`,
      oid: randomOid(),
      status: 1,
      multihash: "sha2-256",
    };

    let recordId: string;
    let hashValue: string;

    const randomObject = () =>
      JSON.stringify({
        test: crypto.randomBytes(12).toString("hex"),
      });

    const commandsAdmin = [
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

    const owner = ethers.Wallet.createRandom().address;

    const commandsUser = [
      ["timestampHashes", () => randomObject()],

      // create record
      ["timestampRecordHashes", () => `${randomObject()} ${randomObject()}`],

      // update record, new version
      [
        "timestampRecordVersionHashes",
        () => `${recordId} ${randomObject()} ${randomObject()}`,
      ],

      // update record, new version
      [
        "timestampVersionHashes",
        () => `${hashValue} ${randomObject()} ${randomObject()}`,
      ],
      ["insertRecordOwner", () => `${recordId} ${owner}`],
      ["revokeRecordOwner", () => `${recordId} ${owner}`],
      ["insertRecordVersionInfo", () => `${recordId} 1 ${randomObject()}`],

      // include new hash to a version
      [
        "appendRecordVersionHashes",
        () => `${recordId} 1 ${randomObject()} ${randomObject()}`,
      ],

      // remove hash from version
      ["detachRecordVersionHash", () => `${recordId} 1 ${hashValue}`],
    ];

    describe.each(commandsAdmin)(
      "Restricted user access when using %s",
      (method: string, params: () => string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
          );
          await execCommand("using token tokenUser.access_token");
        });

        it("should reject not an administrator", async () => {
          expect.assertions(8);
          vi.resetAllMocks();

          await expect(
            execCommand(`timestamp-new ${method} ${params()}`)
          ).rejects.toThrow();

          expectRevertedTransaction(
            mockConsole,
            `Policy error: sender doesn't have the attribute TS:${method}`
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
          await execCommand("using token tokenAdmin.access_token");
        });

        it("should work", async () => {
          expect.assertions(7);
          vi.resetAllMocks();
          await execCommand(`timestamp-new ${method} ${params()}`);
          expectTransaction(mockConsole);
        });
      }
    );

    describe.each(commandsUser)(
      "send transaction for %s",
      (method: string, params: () => string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
          );
          await execCommand("using token tokenUser.access_token");
        });

        it("should work", async () => {
          expect.assertions(7);
          vi.resetAllMocks();
          await execCommand(`timestamp-new ${method} ${params()}`);
          if (method === "timestampRecordHashes") {
            const finalResult = expectTransaction(mockConsole) as {
              recordId: string;
              hashValue: string;
            };
            recordId = finalResult.recordId;
            hashValue = finalResult.hashValue;
          } else {
            expectTransaction(mockConsole);
          }
        });
      }
    );
  });
});
