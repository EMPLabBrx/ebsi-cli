import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto from "node:crypto";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import { expectCollection, expectStatus } from "../utils/api-get-jest.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import {
  expectPostStatus,
  expectStorageCollection,
  expectStorageJsonrpcResponse,
} from "../utils/api-post-jest.js";
import { consoleOutput } from "../utils/utils.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, user2, requesterApp } = config.vitest;

describe("Storage (e2e)", () => {
  beforeAll(async () => {
    await execCommand(
      `using app ${requesterApp.name} ${requesterApp.privateKey}`
    );
    await execCommand("tokenApp: authorisation-old oauth2 storage-api");

    // siop session for user1
    await execCommand(
      `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
    );
    await execCommand("tokenUser1: authorisation-old siop");

    // siop session for user2
    await execCommand("using user null");
    await execCommand(
      `using user ES256K did1 ${user2.privateKey} ${user2.did} ${user2.keyId}`
    );
    await execCommand("tokenUser2: authorisation-old siop");
  });

  describe("Stores", () => {
    it("should get a collection of stores", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand("storage get /stores");
      const data = expectCollection(mockConsole);
      expect(data.items).toStrictEqual(["distributed"]);
    });

    it("should get the distributed store", async () => {
      expect.assertions(1);
      vi.resetAllMocks();
      await execCommand("storage get /stores/distributed");
      expectStatus(mockConsole, 204);
    });
  });

  describe("Files", () => {
    let hash: string;
    it("should get a collection of files", async () => {
      expect.assertions(2);
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand("storage get /stores/distributed/files");
      expectStorageCollection(mockConsole);
    });

    describeWriteOps("create, update, get, and delete", () => {
      const metadata = {
        test: crypto.randomBytes(32).toString("hex"),
      };
      const patchOps = JSON.stringify([
        {
          op: "replace",
          path: "/metadata",
          value: metadata,
        },
      ]);

      it("should store a file", async () => {
        expect.assertions(2);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`storage file insert`);
        const response = consoleOutput(mockConsole, -1) as { hash: string };
        expect(response).toStrictEqual(
          expect.objectContaining({
            hash: expect.any(String) as string,
          })
        );
        hash = response.hash;
        expectPostStatus(mockConsole, 201);
      });

      it("should get a file", async () => {
        expect.assertions(2);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`storage get /stores/distributed/files/${hash}`);
        const response = consoleOutput(mockConsole, -1);
        expect(response).toStrictEqual(expect.stringContaining("Binary data:"));
        expectStatus(mockConsole, 200);
      });

      it("should reject unauthorized access to a file", async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser2");
        vi.resetAllMocks();
        await expect(
          execCommand(`storage get /stores/distributed/files/${hash}`)
        ).rejects.toThrow();
        const error = consoleOutput(mockConsole, -1);
        expect(error).toStrictEqual({
          title: "Not Found",
          status: 404,
          detail: "File not found",
          type: "about:blank",
        });
        expectStatus(mockConsole, 404);
      });

      it(`should reject unauthorized access to patch a file`, async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser2");
        vi.resetAllMocks();

        await expect(
          execCommand(`storage file patch ${hash} ${patchOps}`)
        ).rejects.toThrow();
        const error = consoleOutput(mockConsole, -1);
        expect(error).toStrictEqual({
          title: "Not Found",
          status: 404,
          detail: "File not found",
          type: "about:blank",
        });
        expectPostStatus(mockConsole, 404);
      });

      it(`should patch a file`, async () => {
        expect.assertions(1);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`storage file patch ${hash} ${patchOps}`);
        expectPostStatus(mockConsole, 200);
      });

      it("should get the metadata of a file", async () => {
        expect.assertions(2);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(
          `storage get /stores/distributed/files/${hash}/metadata`
        );
        const data = consoleOutput(mockConsole, -1);
        expect(data).toStrictEqual(metadata);
        expectStatus(mockConsole, 200);
      });

      it("should reject unauthorized access to read the file metadata", async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser2");
        vi.resetAllMocks();
        await expect(
          execCommand(`storage get /stores/distributed/files/${hash}/metadata`)
        ).rejects.toThrow();
        const error = consoleOutput(mockConsole, -1);
        expect(error).toStrictEqual({
          title: "Not Found",
          status: 404,
          detail: "File not found",
          type: "about:blank",
        });
        expectStatus(mockConsole, 404);
      });

      it(`should reject unauthorized access to delete a file`, async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser2");
        vi.resetAllMocks();
        await expect(
          execCommand(`storage file delete ${hash}`)
        ).rejects.toThrow();
        const error = consoleOutput(mockConsole, -1);
        expect(error).toStrictEqual({
          title: "Not Found",
          status: 404,
          detail: "File not found",
          type: "about:blank",
        });
        expectStatus(mockConsole, 404);
      });

      it(`should delete a file`, async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`storage file delete ${hash}`);
        expectStatus(mockConsole, 204);
        vi.resetAllMocks();
        await expect(
          execCommand(`storage get /stores/distributed/files/${hash}`)
        ).rejects.toThrow();
        expectStatus(mockConsole, 404);
      });
    });
  });

  describe("Key Values", () => {
    it("should get a collection of keys", async () => {
      expect.assertions(2);
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand("storage get /stores/distributed/key-values");
      expectStorageCollection(mockConsole);
    });

    describeWriteOps("create, update, get, and delete", () => {
      const key = `test-${crypto.randomBytes(5).toString("hex")}`;
      const value = `value-${crypto.randomBytes(5).toString("hex")}`;
      const value2 = `value-${crypto.randomBytes(5).toString("hex")}`;
      const value3 = `value-${crypto.randomBytes(5).toString("hex")}`;

      it("should store a key", async () => {
        expect.assertions(1);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`storage keyvalue insert ${key} ${value}`);
        expectPostStatus(mockConsole, 201);
      });

      it("should get a key", async () => {
        expect.assertions(2);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`storage get /stores/distributed/key-values/${key}`);
        const response = consoleOutput(mockConsole, -1);
        expect(response).toStrictEqual(value);
        expectStatus(mockConsole, 200);
      });

      it("should reject unauthorized access to a key", async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser2");
        vi.resetAllMocks();
        await expect(
          execCommand(`storage get /stores/distributed/key-values/${key}`)
        ).rejects.toThrow();
        const error = consoleOutput(mockConsole, -1);
        expect(error).toStrictEqual({
          title: "Not Found",
          status: 404,
          detail: "Key not found",
          type: "about:blank",
        });
        expectStatus(mockConsole, 404);
      });

      it(`should reject unauthorized access to delete a key`, async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser2");
        vi.resetAllMocks();
        await expect(
          execCommand(`storage keyvalue delete ${key}`)
        ).rejects.toThrow();
        const error = consoleOutput(mockConsole, -1);
        expect(error).toStrictEqual({
          title: "Not Found",
          status: 404,
          detail: "Key not found",
          type: "about:blank",
        });
        expectStatus(mockConsole, 404);
      });

      it(`should accept same key name for 2 users and different values without mixing them`, async () => {
        expect.assertions(5);
        await execCommand("using token tokenUser2");
        vi.resetAllMocks();

        await execCommand(`storage keyvalue insert ${key} ${value3}`);
        expectPostStatus(mockConsole, 201);

        // get key user2 --> value3
        vi.resetAllMocks();
        await execCommand(`storage get /stores/distributed/key-values/${key}`);
        const response2 = consoleOutput(mockConsole, -1);
        expect(response2).toStrictEqual(value3);
        expectStatus(mockConsole, 200);

        // get key user1 --> value
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`storage get /stores/distributed/key-values/${key}`);
        const response1 = consoleOutput(mockConsole, -1);
        expect(response1).toStrictEqual(value);
        expectStatus(mockConsole, 200);
      });

      it(`should update a key`, async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`storage keyvalue update ${key} ${value2}`);
        expectPostStatus(mockConsole, 200);

        vi.resetAllMocks();
        await execCommand(`storage get /stores/distributed/key-values/${key}`);
        const response = consoleOutput(mockConsole, -1);
        expect(response).toStrictEqual(value2);
        expectStatus(mockConsole, 200);
      });

      it(`should delete a key`, async () => {
        expect.assertions(6);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`storage keyvalue delete ${key}`);
        expectStatus(mockConsole, 204);
        vi.resetAllMocks();
        await expect(
          execCommand(`storage get /stores/distributed/key-values/${key}`)
        ).rejects.toThrow();
        expectStatus(mockConsole, 404);

        await execCommand("using token tokenUser2");
        vi.resetAllMocks();
        await execCommand(`storage keyvalue delete ${key}`);
        expectStatus(mockConsole, 204);
        vi.resetAllMocks();
        await expect(
          execCommand(`storage get /stores/distributed/key-values/${key}`)
        ).rejects.toThrow();
        expectStatus(mockConsole, 404);
      });
    });
  });

  describe("Json RPC", () => {
    it("should get a cassandra response", async () => {
      expect.assertions(2);
      const params = [
        "select * from attribute_storage where did = ? allow filtering",
        user1.did,
      ];
      await execCommand("using token tokenApp");
      vi.resetAllMocks();
      await execCommand(`storage jsonrpc ${JSON.stringify(params)}`);
      expectStorageJsonrpcResponse(mockConsole);
    });

    it("should reject unauthorized access to users", async () => {
      expect.assertions(3);
      const params = [
        "select * from attribute_storage where did = ? allow filtering",
        user1.did,
      ];
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await expect(
        execCommand(`storage jsonrpc ${JSON.stringify(params)}`)
      ).rejects.toThrow();
      const error = consoleOutput(mockConsole, -1);
      expect(error).toStrictEqual({
        title: "Unauthorized",
        status: 401,
        detail: `Invalid JWT: App ${user1.did} not found`,
        type: "about:blank",
      });
      expectPostStatus(mockConsole, 401);
    });
  });
});
