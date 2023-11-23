import { describe, it, expect, vi, beforeAll } from "vitest";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import { expectPostStatus } from "../utils/api-post-jest.js";
import { consoleOutput } from "../utils/utils.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const { user1, requesterApp } = config.vitest;

describe("Ledger (e2e)", () => {
  beforeAll(async () => {
    await execCommand(
      `using app ${requesterApp.name} ${requesterApp.privateKey}`
    );
    await execCommand("tokenLedger: authorisation-old oauth2 ledger-api");

    // siop session for user1
    await execCommand(
      `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
    );
    await execCommand("tokenUser1: authorisation-old siop");
  });

  describe("Besu", () => {
    it("should get a block without authentication", async () => {
      expect.assertions(2);

      vi.resetAllMocks();
      await execCommand("ledger getBlock 123");
      const response = consoleOutput(mockConsole, -1);
      expect(response).toStrictEqual(
        expect.objectContaining({
          id: expect.any(Number) as number,
          jsonrpc: "2.0",
          result: expect.objectContaining({}) as unknown,
        })
      );
      expectPostStatus(mockConsole, 200);
    });

    it("should reject transactions using SIOP tokens", async () => {
      expect.assertions(2);
      await execCommand("using oauth2token"); // removing oauth2 token
      await execCommand("using token tokenUser1");
      const uTx = {
        nonce: 0,
        gasLimit: 221000,
        gasPrice: 0,
        from: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        to: "0x0000000000000000000000000000000000000000",
        value: 0,
        data: "0x12345678901234567890",
      };
      await execCommand(
        `sgnTx: compute signTransaction ${JSON.stringify(uTx)}`
      );
      vi.resetAllMocks();
      await expect(
        execCommand("ledger sendTransaction sgnTx")
      ).rejects.toThrow();
      const error = consoleOutput(mockConsole, -1);
      expect(error).toStrictEqual({
        title: "Unauthorized",
        status: 401,
        detail:
          "This jsonrpc method is restricted to Trusted Apps authorized to use Ledger API",
        type: "about:blank",
      });
    });

    it("should reject the deployment of new smart contracts", async () => {
      expect.assertions(1);
      await execCommand("using token"); // removing siop token
      await execCommand("using oauth2token tokenLedger");
      const uTx = {
        nonce: 0,
        gasLimit: 221000,
        gasPrice: 0,
        from: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        to: "0x0000000000000000000000000000000000000000",
        value: 0,
        data: "0x12345678901234567890",
      };
      await execCommand(
        `sgnTx: compute signTransaction ${JSON.stringify(uTx)}`
      );
      await expect(execCommand("ledger sendTransaction sgnTx")).rejects.toThrow(
        "Deployment of new smart contracts is not allowed"
      );
    });
  });
});
