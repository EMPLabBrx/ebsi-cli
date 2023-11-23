import crypto from "node:crypto";
import { describe, it, expect, vi, beforeAll } from "vitest";
import { ethers } from "ethers";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import {
  expectCollection,
  expectResponse,
  expectStatus,
} from "../utils/api-get-jest.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import {
  expectRevertedTransaction,
  expectTransaction,
} from "../utils/jsonrpc-jest.js";

const { sha256 } = ethers.utils;

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, admin, requesterApp, resourceApp } = config.vitestNew;

describe("Trusted Apps Registry (e2e)", () => {
  beforeAll(async () => {
    if (writeOpsEnabled) {
      if (!config.besuProvider) {
        // oauth2 session to access ledger api
        await execCommand(
          `using app ${requesterApp.name} ${requesterApp.privateKey}`
        );
        await execCommand("tokenLedger: authorisation-new oauth2 ledger-api");
        await execCommand("using oauth2token tokenLedger");
      }

      // siop session for the user
      await execCommand(
        `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
      );
      await execCommand("tokenUser: authorisation-new siop");

      // siop session for the admin
      await execCommand("using user null");
      await execCommand(
        `using user ES256K did1 ${admin.privateKey} ${admin.did} ${admin.keyId}`
      );
      await execCommand("tokenAdmin: authorisation-new siop");
    }
  });

  describe("GET /apps", () => {
    let publicKeyId: string;
    let authorizationId: string;

    it("should get a collection of apps", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand("tar-new get /apps");
      expectCollection<{
        id: string;
        name: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
    });

    it("should get an app", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`tar-new get /apps/${requesterApp.name}`);
      const data = expectResponse<{
        publicKeys: string[];
      }>(mockConsole, {
        applicationId: requesterApp.id,
        name: requesterApp.name,
        domain: expect.any(String) as string,
        administrators: expect.arrayContaining([
          expect.any(String) as string,
        ]) as string[],
        publicKeys: expect.arrayContaining([
          expect.any(String) as string,
        ]) as string[],
        info: expect.objectContaining({}) as unknown,
        authorizations: expect.arrayContaining([]) as unknown[],
        revocation: null,
      });
      expectStatus(mockConsole, 200);
      publicKeyId = sha256(Buffer.from(data.publicKeys[0], "base64"));
    });

    it("should get a collection of apps filtered by public_key_id", async () => {
      expect.assertions(4);
      vi.resetAllMocks();
      await execCommand(`tar-new get /apps?public_key_id=${publicKeyId}`);
      const data = expectCollection<{
        id: string;
        name: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
      expect(data.items).toStrictEqual([
        {
          id: requesterApp.id,
          name: requesterApp.name,
          href: requesterApp.kid,
        },
      ]);
    });

    it("should get the public keys of an app", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`tar-new get /apps/${requesterApp.name}/public-keys`);
      expectCollection<{
        id: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
    });

    it("should get a public key from an app", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(
        `tar-new get /apps/${requesterApp.name}/public-keys/${publicKeyId}`
      );
      expectResponse(mockConsole, {
        applicationId: requesterApp.id,
        publicKey: expect.any(String) as string,
        status: expect.any(String) as string,
      });
      expectStatus(mockConsole, 200);
    });

    it("should get the authorizations of an app", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`tar-new get /apps/${resourceApp.name}/authorizations`);
      expectCollection<{
        authorizationId: string;
        requesterApplicationName: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
    });

    it("should get the authorizations of an app filtered by requesterApplicationId", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(
        `tar-new get /apps/${
          resourceApp.name
        }/authorizations?requesterApplicationName=${
          requesterApp.name.split("_")[0]
        }`
      );
      const data = expectCollection<{
        authorizationId: string;
        requesterApplicationName: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
      authorizationId = data.items[0].authorizationId;
    });

    it("should get an authorization from an app", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(
        `tar-new get /apps/${resourceApp.name}/authorizations/${authorizationId}`
      );
      expectResponse(mockConsole, {
        authorizationId,
        resourceApplicationId: resourceApp.id,
        requesterApplicationId: expect.any(String) as string,
        resourceApplicationName: resourceApp.name,
        requesterApplicationName: requesterApp.name.split("_")[0],
        iss: expect.any(String) as string,
        status: expect.any(String) as string,
      });
      expectStatus(mockConsole, 200);
    });
  });

  describeWriteOps("POST /jsonrpc", () => {
    const now = Math.round(Date.now() / 1000);

    const createPublicKey = () => {
      const privateKey = crypto.randomBytes(32).toString("hex");
      const publicKeyPem = new EbsiWallet(privateKey).getPublicKey({
        format: "pem",
      });
      const buffer = Buffer.from(publicKeyPem);
      return {
        id: sha256(buffer),
        base64: buffer.toString("base64"),
      };
    };

    const newApp = {
      id: "",
      name: `testapp-${crypto.randomBytes(5).toString("hex")}`,
      publicKeys: [createPublicKey()],
      info: { data: crypto.randomBytes(12).toString("hex") },
      appAdmin: EbsiWallet.createDid(),
    };
    newApp.id = ethers.utils.sha256(ethers.utils.toUtf8Bytes(newApp.name));

    const newApp2 = {
      id: "",
      name: `testapp-${crypto.randomBytes(5).toString("hex")}`,
    };
    newApp2.id = ethers.utils.sha256(ethers.utils.toUtf8Bytes(newApp2.name));

    const auth = {
      id: "",
      name: newApp.name,
      authorizedAppName: requesterApp.name,
      iss: admin.did,
      status: 1,
    };
    auth.id = sha256(
      ethers.utils.defaultAbiCoder.encode(
        ["bytes32", "bytes32", "string", "uint8"],
        [newApp.id, requesterApp.id, auth.iss, auth.status]
      )
    );
    // const policyId = `policy-${crypto.randomBytes(10).toString("hex")}`;

    const commands1 = [
      ["insertApp", newApp.name],
      ["insertApp", newApp2.name],
      ["insertAppPublicKey", `${newApp.id} ${newApp.publicKeys[0].base64}`],
      ["insertAppInfo", `${newApp.id} ${JSON.stringify(newApp.info)}`],
      [
        "insertAuthorization",
        `${auth.name} ${auth.authorizedAppName} ${auth.iss} ${auth.status}`,
      ],
      ["insertAppAdministrator", `${newApp.id} ${newApp.appAdmin}`],
      ["deleteAppAdministrator", `${newApp.id} ${newApp.appAdmin}`],
      ["updateApp", `${newApp.id} 1`],
      ["updateAppPublicKey", `${newApp.publicKeys[0].id} 2`],
      ["updateAuthorization", `${auth.id} 2`],
      ["insertRevocation", `${newApp.id} ${admin.did} ${now}`],
    ];

    const commands2 = [
      ["insertApp", `testapp-${crypto.randomBytes(5).toString("hex")}`],
      ...commands1.slice(2, commands1.length - 1),
      ["insertRevocation", `${newApp2.id} ${admin.did} ${now}`],
    ];

    describe.each(commands1)(
      "send transaction for %s",
      (method: string, params: string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${admin.privateKey} ${admin.did} ${admin.keyId}`
          );
          await execCommand("using token tokenAdmin");
          await execCommand("using oauth2token tokenLedger");
        });
        it("should work", async () => {
          expect.assertions(7);
          vi.resetAllMocks();
          await execCommand(`tar-new ${method} ${params}`);
          expectTransaction(mockConsole);
        });
      }
    );

    describe.each(commands2)(
      "Restricted user access when using %s",
      (method: string, params: string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
          );
          await execCommand("using token tokenUser");
        });

        it("should reject not an administrator", async () => {
          expect.assertions(8);
          vi.resetAllMocks();
          await expect(
            execCommand(`tar-new ${method} ${params}`)
          ).rejects.toThrow();

          if (["insertApp", "insertRevocation", "updateApp"].includes(method)) {
            expectRevertedTransaction(
              mockConsole,
              `Policy error: sender doesn't have the attribute TAR:${method}`
            );
          } else {
            expectRevertedTransaction(
              mockConsole,
              `Policy error: sender is not controller of any of the adminitrators of app '${newApp.name}' and it doesn't have the attribute TAR:${method}`
            );
          }
        });
      }
    );
  });
});
