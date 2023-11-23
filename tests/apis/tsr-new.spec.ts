import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto from "node:crypto";
import { ethers } from "ethers";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import {
  expectRevertedTransaction,
  expectTransaction,
} from "../utils/jsonrpc-jest.js";
import { computeSchemaId } from "../../src/utils/index.js";
import { PaginatedList } from "../../src/interfaces/index.js";

const { sha256 } = ethers.utils;

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, admin, requesterApp } = config.vitestNew;

describe("Trusted Schemas Registry (e2e)", () => {
  beforeAll(async () => {
    // siop session for the user
    await execCommand(
      `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
    );
    await execCommand("tokenUser: authorisation-new siop");

    if (writeOpsEnabled) {
      if (!config.besuProvider) {
        // oauth2 session to access ledger api
        await execCommand(
          `using app ${requesterApp.name} ${requesterApp.privateKey}`
        );
        await execCommand("tokenLedger: authorisation-new oauth2 ledger-api");
      }

      // siop session for the admin
      await execCommand("using user null");
      await execCommand(
        `using user ES256K did1 ${admin.privateKey} ${admin.did} ${admin.keyId}`
      );
      await execCommand("tokenAdmin: authorisation-new siop");
    }
  });

  describe("GET /schemas", () => {
    let schemaId: string;
    let schemaRevisionId: string;
    let metadataId: string;
    it("should get a collection of schemas", async () => {
      expect.assertions(1);
      const data = await execCommand<PaginatedList<{ schemaId: string }>>(
        "tsr-new get /schemas"
      );
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
      schemaId = data.items[0].schemaId;
    });

    it("should get a schema", async () => {
      expect.assertions(1);
      const data = await execCommand(`tsr-new get /schemas/${schemaId}`);
      expect(data).toBeDefined();
    });

    it("should get the revisions of a schema", async () => {
      expect.assertions(1);
      const data = await execCommand<
        PaginatedList<{ schemaRevisionId: string }>
      >(`tsr-new get /schemas/${schemaId}/revisions`);
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
      schemaRevisionId = data.items[0].schemaRevisionId;
    });

    it("should get a revision from a schema", async () => {
      expect.assertions(1);
      const data = await execCommand(
        `tsr-new get /schemas/${schemaId}/revisions/${schemaRevisionId}`
      );
      expect(data).toBeDefined();
    });

    it("should get metadata collection from a revision from a schema", async () => {
      expect.assertions(1);
      const data = await execCommand<PaginatedList<{ metadataId: string }>>(
        `tsr-new get /schemas/${schemaId}/revisions/${schemaRevisionId}/metadata`
      );
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

    it("should get the metadata content from a revision from a schema", async () => {
      expect.assertions(1);
      const data = await execCommand(
        `tsr-new get /schemas/${schemaId}/revisions/${schemaRevisionId}/metadata/${metadataId}`
      );
      expect(data).toBeDefined();
    });
  });

  describeWriteOps("POST /jsonrpc", () => {
    const schema = {
      "@context": "https://ebsi.eu",
      type: "Schema",
      name: "example",
      title: "test schema",
      data: crypto.randomBytes(16).toString("hex"),
    };
    const schema2 = {
      ...schema,
      title: "test schema v2",
    };
    let schemaId: string;
    const serializedSchema = JSON.stringify(schema);
    const serializedSchema2 = JSON.stringify(schema2);
    const serializedSchemaBuffer = Buffer.from(serializedSchema);
    const schemaRevisionId = sha256(serializedSchemaBuffer);

    const commands = [
      ["insertSchema", () => JSON.stringify(schema)],
      ["updateSchema", () => `${schemaId} ${serializedSchema2}`],
      ["updateMetadata", () => `${schemaRevisionId}`],
    ];

    describe.each(commands)(
      "Restricted user access when using %s",
      (method: string, params: () => string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
          );
          await execCommand("using token tokenUser");
          schemaId = await computeSchemaId(schema, "base16");
        });
        it("should reject not authorized users", async () => {
          expect.assertions(8);
          vi.resetAllMocks();
          await expect(
            execCommand(`tsr-new ${method} ${params()}`)
          ).rejects.toThrow();
          expectRevertedTransaction(
            mockConsole,
            `Policy error: sender doesn't have the attribute TSR:${method}`
          );
        });
      }
    );

    describe.each(commands)(
      "send transaction for %s",
      (method: string, params: () => string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${admin.privateKey} ${admin.did} ${admin.keyId}`
          );
          await execCommand("using token tokenAdmin");
          await execCommand("using oauth2token tokenLedger");
          schemaId = await computeSchemaId(schema, "base16");
        });
        it("should work", async () => {
          expect.assertions(7);
          vi.resetAllMocks();
          await execCommand(`tsr-new ${method} ${params()}`);
          expectTransaction(mockConsole);
        });
      }
    );
  });
});
