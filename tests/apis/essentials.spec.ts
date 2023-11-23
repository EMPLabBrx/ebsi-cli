import { describe, it, expect, vi } from "vitest";
import { execCommand } from "../../src/app.js";
import { expectCollection, expectResponse } from "../utils/api-get-jest.js";
import ebsiExtended from "../utils/ebsi-extended.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const auth2 = "Authorisation API v2";
const auth3 = "Authorisation API v3";
const did4 = "DIDR API v4";
const ledger3 = "Ledger API v3";
const tar3 = "TAR API v3";
const tar4 = "TAR API v4";
const tir4 = "TIR API v4";
const tpr2 = "TPR API v2";
const tsr2 = "TSR API v2";
const storage3 = "Storage API v3";

describe("Essential e2e tests", () => {
  describe.each([
    ["timestamp", [auth2, did4, ledger3, tar3]],
    ["storage", [auth2, tar3]],
    ["ledger", [auth2, tar3, tar4]],
    ["notifications", [auth2, did4, storage3, tar3]],
    ["authorisation", [did4, tir4]],
    ["onboarding", ["ebsi-apis"]],
    ["did", [auth2, auth3, ledger3, tar3]],
    ["datahub", [auth2, storage3, tar3]],
    ["tar", [auth2, did4]],
    ["tir", [auth2, auth3, did4, ledger3, tar3, tpr2, tsr2]],
    ["tpr", [auth2, did4, ledger3, tar3]],
    ["tsr", [auth2, did4, ledger3, tar3, tsr2]],
  ])("Health for %s", (api: string, deps: string[]) => {
    it(`should get health`, async () => {
      expect.assertions(1);
      const info = {};
      deps.forEach((d) => {
        info[d] = { status: "up" };
      });
      const response = await execCommand(`${api} get /health`);
      expect(response).toStrictEqual({
        status: "ok",
        info,
        error: {},
        details: info,
      });
    });
  });

  describe("Hash algorithms for timestamp", () => {
    it("should get hash algorithm 0", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`timestamp get /hash-algorithms/0`);
      expectResponse(mockConsole, {
        outputLengthBits: 256,
        ianaName: "sha-256",
        oid: "2.16.840.1.101.3.4.2.1",
        status: "active",
        multihash: "sha2-256",
      });
    });

    it("should get hash algorithm 1", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`timestamp get /hash-algorithms/1`);
      expectResponse(mockConsole, {
        outputLengthBits: 256,
        ianaName: "sha-256",
        oid: "2.16.840.1.101.3.4.2.1",
        status: "active",
        multihash: "sha2-256",
      });
    });

    it.skip("should get hash algorithm 2", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`timestamp get /hash-algorithms/2`);
      expectResponse(mockConsole, {
        outputLengthBits: 384,
        ianaName: "sha-384",
        oid: "2.16.840.1.101.3.4.2.2",
        status: "active",
        multihash: "sha2-384",
      });
    });

    it("should get hash algorithm 3", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`timestamp get /hash-algorithms/3`);
      expectResponse(mockConsole, {
        outputLengthBits: 512,
        ianaName: "sha-512",
        oid: "2.16.840.1.101.3.4.2.3",
        status: "active",
        multihash: "sha2-512",
      });
    });

    it("should get hash algorithm 4", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`timestamp get /hash-algorithms/4`);
      expectResponse(mockConsole, {
        outputLengthBits: 224,
        ianaName: "sha3-224",
        oid: "2.16.840.1.101.3.4.2.7",
        status: "active",
        multihash: "sha3-224",
      });
    });

    it("should get hash algorithm 5", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`timestamp get /hash-algorithms/5`);
      expectResponse(mockConsole, {
        outputLengthBits: 256,
        ianaName: "sha3-256",
        oid: "2.16.840.1.101.3.4.2.8",
        status: "active",
        multihash: "sha3-256",
      });
    });

    it("should get hash algorithm 6", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`timestamp get /hash-algorithms/6`);
      expectResponse(mockConsole, {
        outputLengthBits: 384,
        ianaName: "sha3-384",
        oid: "2.16.840.1.101.3.4.2.9",
        status: "active",
        multihash: "sha3-384",
      });
    });

    it("should get hash algorithm 7", async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`timestamp get /hash-algorithms/7`);
      expectResponse(mockConsole, {
        outputLengthBits: 512,
        ianaName: "sha3-512",
        oid: "2.16.840.1.101.3.4.2.10",
        status: "active",
        multihash: "sha3-512",
      });
    });
  });

  describe.each([
    ["timestamp", "/timestamps"],
    ["did", "/identifiers"],
    ["tar", "/apps"],
    ["tir", "/issuers"],
    ["tpr", "/users"],
    ["tsr", "/schemas"],
  ])("Registry %s", (api, collection) => {
    it(`should get from ${api} the collection ${collection}`, async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`${api} get ${collection}`);
      expectCollection(mockConsole);
    });
  });
});
