import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto from "node:crypto";
import { ethers } from "ethers";
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

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, admin, requesterApp } = config.vitest;

describe("Trusted Policies Registry (e2e)", () => {
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

      // siop session for the user
      await execCommand("using user null");
      await execCommand(
        `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
      );
      await execCommand("tokenUser: authorisation-old siop");
    }
  });

  describe("GET /policies", () => {
    let policyName: string;
    it("should get a collection of policies", async () => {
      expect.assertions(6);
      vi.resetAllMocks();
      await execCommand("tpr get /policies");
      let data = expectCollection<{
        policyName: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
      expect(data.items.length > 0).toBeTruthy();

      const urlLastPage = data.links.last.slice(
        data.links.last.indexOf("/policies")
      );
      vi.resetAllMocks();
      await execCommand(`tpr get ${urlLastPage}`);
      data = expectCollection<{
        policyName: string;
        href: string;
      }>(mockConsole);
      policyName = data.items[data.items.length - 1].policyName;
    });

    it("should get a policy", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`tpr get /policies/${policyName}`);
      expectResponse(
        mockConsole,
        expect.objectContaining({
          description: expect.any(String) as string,
          operationType: "AND",
          policyConditions: expect.arrayContaining([
            {
              attributeName: expect.any(String) as string,
              attributeOperation: "EQUAL",
              name: expect.any(String) as string,
              typeOfValue: expect.any(String) as string,
              value: expect.anything() as unknown,
            },
          ]) as unknown[],
          policyId: expect.any(String) as string,
          policyName,
          status: expect.any(Boolean) as boolean,
        })
      );
      expectStatus(mockConsole, 200);
    });
  });

  describe("GET /users", () => {
    let address: string;
    it("should get a collection of users", async () => {
      expect.assertions(4);
      vi.resetAllMocks();
      await execCommand("tpr get /users");
      const data = expectCollection<{
        address: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
      expect(data.items.length > 0).toBeTruthy();
      address = data.items[0].address;
    });

    it("should get a user", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`tpr get /users/${address}`);
      expectResponse(
        mockConsole,
        expect.objectContaining({
          address,
          attributes: expect.objectContaining({}) as unknown,
        })
      );
      expectStatus(mockConsole, 200);
    });
  });

  describeWriteOps("POST /jsonrpc", () => {
    const newUser = {
      address: ethers.Wallet.createRandom().address,
      attributeNames: ["attr1", "attr2", "attr3"],
      attributeValues: [true, false, true],
    };

    let newPolicy: {
      name: string;
      id: string;
    };

    const commands = [
      // users
      [
        "insertUserAttributes",
        () =>
          `${newUser.address} ${JSON.stringify(
            newUser.attributeNames
          )} ${JSON.stringify(newUser.attributeValues)}`,
      ],
      ["updateUserAttribute", () => `${newUser.address} attr2 true`],
      ["deleteUserAttribute", () => `${newUser.address} attr3`],
      // policies
      ["insertPolicy", () => `${newPolicy.name} true ["test policy"]`],
      // functions by name
      ["addPolicyConditions", () => `${newPolicy.name} condition1 true`],
      ["deletePolicyCondition", () => `${newPolicy.name} 1`],
      [
        "updatePolicy",
        () => `${newPolicy.name} ["test policy new description 1"]`,
      ],
      ["deactivatePolicy", () => newPolicy.name],
      ["activatePolicy", () => newPolicy.name],
      // functions by id
      ["addPolicyConditions", () => `${newPolicy.id} condition2 true`],
      ["deletePolicyCondition", () => `${newPolicy.id} 1`],
      [
        "updatePolicy",
        () => `${newPolicy.id} ["test policy new description 2"]`,
      ],
      ["deactivatePolicy", () => newPolicy.id],
      ["activatePolicy", () => newPolicy.id],
    ];

    beforeAll(async () => {
      const policyPage = await execCommand<{
        total: number;
      }>("tpr get /policies");
      newPolicy = {
        name: `test-${crypto.randomBytes(6).toString("hex")}`,
        id: String(policyPage.total),
      };
    });

    describe.each(commands)(
      "Restricted user access when using %s",
      (method: string, params: () => string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
          );
          await execCommand("using token tokenUser");
        });
        it("should reject not authorized users", async () => {
          expect.assertions(8);
          vi.resetAllMocks();
          await expect(
            execCommand(`tpr ${method} ${params()}`)
          ).rejects.toThrow();
          expectRevertedTransaction(mockConsole, "is missing role");
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
        });
        it("should work", async () => {
          expect.assertions(7);
          vi.resetAllMocks();
          await execCommand(`tpr ${method} ${params()}`);
          expectTransaction(mockConsole);
        });
      }
    );
  });
});
