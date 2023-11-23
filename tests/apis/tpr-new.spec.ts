import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto from "node:crypto";
import { ethers } from "ethers";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import { expectResponse, expectStatus } from "../utils/api-get-jest.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import { PaginatedList } from "../../src/interfaces/index.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, tprOperator, requesterApp } = config.vitestNew;

describe("Trusted Policies Registry (e2e)", () => {
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

      // siop session for the admin
      await execCommand(
        `using user ES256K did1 ${tprOperator.privateKey} ${tprOperator.did} ${tprOperator.keyId}`
      );
      await execCommand("tokenAdmin: authorisation-new siop");

      // siop session for the user
      await execCommand("using user null");
      await execCommand(
        `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
      );
      await execCommand("tokenUser: authorisation-new siop");
    }
  });

  describe("GET /policies", () => {
    let policyName: string;
    it("should get a collection of policies", async () => {
      expect.assertions(1);
      let result = await execCommand<
        PaginatedList<{
          policyName: string;
          href: string;
        }>
      >("tpr-new get /policies");
      expect(result.items.length > 0).toBeTruthy();

      const urlLastPage = result.links.last.slice(
        result.links.last.indexOf("/policies")
      );

      result = await execCommand<
        PaginatedList<{
          policyName: string;
          href: string;
        }>
      >(`tpr-new get ${urlLastPage}`);

      policyName = result.items[result.items.length - 1].policyName;
    });

    it("should get a policy", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`tpr-new get /policies/${policyName}`);
      expectResponse(
        mockConsole,
        expect.objectContaining({
          description: expect.any(String) as string,
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
      expect.assertions(2);
      const result = await execCommand<
        PaginatedList<{
          address: string;
          href: string;
        }>
      >("tpr-new get /users");
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
      address = result.items[0].address;
    });

    it("should get a user", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`tpr-new get /users/${address}`);
      expectResponse(
        mockConsole,
        expect.objectContaining({
          address,
          attributes: expect.arrayContaining([]) as unknown,
        })
      );
      expectStatus(mockConsole, 200);
    });
  });

  describeWriteOps("POST /jsonrpc", () => {
    const newUser = {
      address: ethers.Wallet.createRandom().address,
      attributeNames: ["attr1", "attr2", "attr3"],
    };

    let newPolicy: {
      name: string;
      id: string;
    };

    const commands = [
      // users
      [
        "insertUserAttributes",
        () => `${newUser.address} ${JSON.stringify(newUser.attributeNames)}`,
      ],
      ["deleteUserAttribute", () => `${newUser.address} attr3`],
      // policies
      ["insertPolicy", () => `${newPolicy.name} ["test policy"]`],
      // functions by name
      [
        "updatePolicy",
        () => `${newPolicy.name} ["test policy new description 1"]`,
      ],
      ["deactivatePolicy", () => newPolicy.name],
      ["activatePolicy", () => newPolicy.name],
      // functions by id
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
      }>("tpr-new get /policies");
      newPolicy = {
        name: `test-${crypto.randomBytes(6).toString("hex")}`,
        id: String(policyPage.total + 1),
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
          expect.assertions(1);
          await expect(
            execCommand(`tpr-new ${method} ${params()}`)
          ).rejects.toThrow("is missing role");
        });
      }
    );

    describe.each(commands)(
      "send transaction for %s",
      (method: string, params: () => string) => {
        beforeAll(async () => {
          await execCommand("using user null");
          await execCommand(
            `using user ES256K did1 ${tprOperator.privateKey} ${tprOperator.did} ${tprOperator.keyId}`
          );
          await execCommand("using token tokenAdmin");
        });
        it("should work", async () => {
          expect.assertions(1);
          await expect(
            execCommand(`tpr-new ${method} ${params()}`)
          ).resolves.toBeDefined();
        });
      }
    );
  });
});
