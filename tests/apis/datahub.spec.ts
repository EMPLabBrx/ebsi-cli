import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto from "node:crypto";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import { expectStatus } from "../utils/api-get-jest.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import {
  expectPostStatus,
  expectStorageCollection,
} from "../utils/api-post-jest.js";
import { consoleOutput } from "../utils/utils.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, user2, user3, np } = config.vitest;

describe("Proxy Data Hub (e2e)", () => {
  let attributeIdPrivate: string;
  let attributeIdPublic: string;
  let attributeIdShared: string;
  let attributeIdSharedNp: string;
  const jwkStringNp = Buffer.from(
    np.ES256K.privateKeyBase64,
    "base64"
  ).toString();

  const randomData = () =>
    JSON.stringify({ data: crypto.randomBytes(32).toString("hex") });

  const loadUser1 = async () => {
    await execCommand("using user null");
    await execCommand(
      `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
    );
  };

  const loadNp = async () => {
    await execCommand("using user null");
    await execCommand(`using user ES256K did2 ${jwkStringNp} ${np.ES256K.did}`);
  };

  beforeAll(async () => {
    if (writeOpsEnabled) {
      // siop session for user2
      await execCommand(
        `using user ES256K did1 ${user2.privateKey} ${user2.did} ${user2.keyId}`
      );
      await execCommand("tokenUser2: authorisation-old siop");

      // siop session for user3
      await execCommand("using user null");
      await execCommand(
        `using user ES256K did1 ${user3.privateKey} ${user3.did} ${user3.keyId}`
      );
      await execCommand("tokenUser3: authorisation-old siop");
    }

    // siop session for natural person
    await loadNp();
    await execCommand(
      `tokenNp: authorisation-old siop ES256K ${np.ES256K.vcJwt}`
    );

    // siop session for user1
    await loadUser1();
    await execCommand("tokenUser1: authorisation-old siop");
  });

  it("should get a collection of attributes - legal entity", async () => {
    expect.assertions(2);
    await execCommand("using token tokenUser1");
    vi.resetAllMocks();
    await execCommand("datahub get /attributes");
    expectStorageCollection(mockConsole);
  });

  it("should get a collection of attributes - natural person", async () => {
    expect.assertions(2);
    await execCommand("using token tokenNp");
    vi.resetAllMocks();
    await execCommand("datahub get /attributes");
    expectStorageCollection(mockConsole);
  });

  describeWriteOps("create, get, and delete", () => {
    it("should create a private attribute - legal entity", async () => {
      expect.assertions(2);
      await loadUser1();
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand(`datahub insert ${randomData()} private`);
      const attribute = consoleOutput(mockConsole, -1) as { hash: string };
      expect(attribute).toStrictEqual(
        expect.objectContaining({
          hash: expect.any(String) as string,
        })
      );
      attributeIdPrivate = attribute.hash;
      expectPostStatus(mockConsole, 201);
    });

    it("should create a private attribute - natural person", async () => {
      expect.assertions(2);
      await loadNp();
      await execCommand("using token tokenNp");
      vi.resetAllMocks();
      await execCommand(`datahub insert ${randomData()} private`);
      const attribute = consoleOutput(mockConsole, -1) as { hash: string };
      expect(attribute).toStrictEqual(
        expect.objectContaining({
          hash: expect.any(String) as string,
        })
      );
      expectPostStatus(mockConsole, 201);
    });

    it("should create a public attribute", async () => {
      expect.assertions(2);
      await loadUser1();
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand(`datahub insert ${randomData()} shared`);
      const attribute = consoleOutput(mockConsole, -1) as { hash: string };
      expect(attribute).toStrictEqual(
        expect.objectContaining({
          hash: expect.any(String) as string,
        })
      );
      expectPostStatus(mockConsole, 201);
      attributeIdPublic = attribute.hash;
    });

    it("should create a shared attribute", async () => {
      expect.assertions(2);
      await loadUser1();
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand(`datahub insert ${randomData()} shared ${user2.did}`);
      const attribute = consoleOutput(mockConsole, -1) as { hash: string };
      expect(attribute).toStrictEqual(
        expect.objectContaining({
          hash: expect.any(String) as string,
        })
      );
      attributeIdShared = attribute.hash;
      expectPostStatus(mockConsole, 201);
    });

    it("should create a shared attribute with a natural person", async () => {
      expect.assertions(2);
      await loadUser1();
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand(
        `datahub insert ${randomData()} shared ${np.ES256K.did}`
      );
      const attribute = consoleOutput(mockConsole, -1) as { hash: string };
      expect(attribute).toStrictEqual(
        expect.objectContaining({
          hash: expect.any(String) as string,
        })
      );
      attributeIdSharedNp = attribute.hash;
      expectPostStatus(mockConsole, 201);
    });

    it("should get a private attribute", async () => {
      expect.assertions(2);
      await loadUser1();
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand(`datahub get /attributes/${attributeIdPrivate}`);
      const attribute = consoleOutput(mockConsole, -1);
      expectStatus(mockConsole, 200);
      expect(attribute).toStrictEqual(
        expect.objectContaining({
          storageUri: `${config.api.storage.url}/stores/distributed`,
          visibility: "private",
          sharedWith: "",
          did: user1.did,
          contentType: expect.any(String) as string,
          dataLabel: expect.any(String) as string,
          data: expect.any(String) as string,
          hash: expect.any(String) as string,
        })
      );
    });

    it("should get a public attribute", async () => {
      expect.assertions(2);
      await execCommand("using token"); // removing token
      vi.resetAllMocks();
      await execCommand(`datahub get /attributes/${attributeIdPublic}`);
      const attribute = consoleOutput(mockConsole, -1);
      expectStatus(mockConsole, 200);
      expect(attribute).toStrictEqual(
        expect.objectContaining({
          storageUri: `${config.api.storage.url}/stores/distributed`,
          visibility: "shared",
          sharedWith: "",
          did: user1.did,
          contentType: expect.any(String) as string,
          dataLabel: expect.any(String) as string,
          data: expect.any(String) as string,
          hash: expect.any(String) as string,
        })
      );
    });

    describe.each([
      ["owner", "tokenUser1"],
      ["shared with user 2", "tokenUser2"],
      ["shared with natural person", "tokenNp"],
    ])("shared attribute using %s", (user, token) => {
      it(`should get a shared attribute (${user})`, async () => {
        expect.assertions(2);
        await execCommand(`using token ${token}`);
        vi.resetAllMocks();
        const npTest = token === "tokenNp";
        const id = npTest ? attributeIdSharedNp : attributeIdShared;
        await execCommand(`datahub get /attributes/${id}`);
        const attribute = consoleOutput(mockConsole, -1);
        expectStatus(mockConsole, 200);
        expect(attribute).toStrictEqual(
          expect.objectContaining({
            storageUri: `${config.api.storage.url}/stores/distributed`,
            visibility: "shared",
            sharedWith: npTest ? np.ES256K.did : user2.did,
            did: user1.did,
            contentType: expect.any(String) as string,
            dataLabel: expect.any(String) as string,
            data: expect.any(String) as string,
            hash: expect.any(String) as string,
          })
        );
      });
    });

    it("should reject unauthorized access to a private attribute", async () => {
      expect.assertions(3);
      await execCommand("using token tokenUser2");
      vi.resetAllMocks();
      await expect(
        execCommand(`datahub get /attributes/${attributeIdPrivate}`)
      ).rejects.toThrow();
      const error = consoleOutput(mockConsole, -1);
      expect(error).toStrictEqual({
        title: "Forbidden",
        status: 403,
        type: "about:blank",
      });
      expectStatus(mockConsole, 403);
    });

    it("should reject unauthorized access to a shared attribute", async () => {
      expect.assertions(3);
      await execCommand("using token tokenUser3");
      vi.resetAllMocks();
      await expect(
        execCommand(`datahub get /attributes/${attributeIdShared}`)
      ).rejects.toThrow();
      const error = consoleOutput(mockConsole, -1);
      expect(error).toStrictEqual({
        title: "Forbidden",
        status: 403,
        type: "about:blank",
      });
      expectStatus(mockConsole, 403);
    });

    describe.each([
      ["private", () => attributeIdPrivate],
      ["public", () => attributeIdPublic],
      ["shared", () => attributeIdShared],
    ])("%s attribute", (type, param) => {
      const patchOps = JSON.stringify([
        {
          op: "replace",
          path: "/contentType",
          value: "application/ld+json",
        },
      ]);
      it(`should reject unauthorized access to patch a ${type} attribute`, async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser2");
        vi.resetAllMocks();

        await expect(
          execCommand(`datahub patch ${param()} ${patchOps}`)
        ).rejects.toThrow();
        const error = consoleOutput(mockConsole, -1);
        expect(error).toStrictEqual({
          title: "Forbidden",
          status: 403,
          detail: `${user2.did} is not the owner of attribute ${param()}`,
          type: "about:blank",
        });
        expectPostStatus(mockConsole, 403);
      });

      it(`should patch a ${type} attribute`, async () => {
        expect.assertions(1);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`datahub patch ${param()} ${patchOps}`);
        expectPostStatus(mockConsole, 200);
      });

      it(`should reject unauthorized access to delete a ${type} attribute`, async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser2");
        vi.resetAllMocks();
        await expect(
          execCommand(`datahub delete ${param()}`)
        ).rejects.toThrow();
        const error = consoleOutput(mockConsole, -1);
        expect(error).toStrictEqual({
          title: "Forbidden",
          status: 403,
          detail: `${user2.did} is not the owner of attribute ${param()}`,
          type: "about:blank",
        });
        expectStatus(mockConsole, 403);
      });

      it(`should delete a ${type} attribute`, async () => {
        expect.assertions(3);
        await execCommand("using token tokenUser1");
        vi.resetAllMocks();
        await execCommand(`datahub delete ${param()}`);
        expectStatus(mockConsole, 204);
        vi.resetAllMocks();
        await expect(
          execCommand(`datahub get /attributes/${param()}`)
        ).rejects.toThrow();
        expectStatus(mockConsole, 404);
      });
    });
  });
});
