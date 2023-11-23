import { describe, it, expect, vi } from "vitest";
import { execCommand } from "../../src/app.js";
import { expectCollection } from "../utils/api-get-jest.js";
import ebsiExtended from "../utils/ebsi-extended.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const auth4 = "Authorisation API v4";
const did5 = "DIDR API v5";
const ledger4 = "Ledger API v4";
const tar4 = "TAR API v4";
const tir5 = "TIR API v5";
const tpr3 = "TPR API v3";
const tsr3 = "TSR API v3";

describe("Essential e2e tests", () => {
  describe.each([
    ["ledger", [tar4]],
    ["authorisation", [did5, tar4, tir5, tpr3, tsr3]],
    ["did", [auth4, ledger4, tar4]],
    ["tar", [auth4, did5]],
    ["tir", [auth4, did5, ledger4, tar4, tpr3, tsr3]],
    ["tpr", [auth4, did5, ledger4, tar4]],
    ["tsr", [auth4, did5, ledger4, tar4, tsr3]],
    ["timestamp", [auth4, did5, ledger4, tar4]],
  ])("Health for %s", (api: string, deps: string[]) => {
    it(`should get health`, async () => {
      expect.assertions(1);
      const info = {};
      deps.forEach((d) => {
        info[d] = { status: "up" };
      });
      const response = await execCommand(`${api}-new get /health`);
      expect(response).toStrictEqual({
        status: "ok",
        info,
        error: {},
        details: info,
      });
    });
  });

  describe.each([
    ["did", "/identifiers"],
    ["tar", "/apps"],
    ["tir", "/issuers"],
    ["tpr", "/users"],
    ["tsr", "/schemas"],
    ["timestamp", "/timestamps"],
  ])("Registry %s", (api, collection) => {
    it(`should get from ${api} the collection ${collection}`, async () => {
      expect.assertions(2);
      vi.resetAllMocks();
      await execCommand(`${api} get ${collection}`);
      expectCollection(mockConsole);
    });
  });
});
