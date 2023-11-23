import { describe, it, expect, vi, beforeAll } from "vitest";
import { execCommand } from "../../src/app.js";

const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

describe("Holder Wallet", () => {
  const credentials: string[] = [];
  beforeAll(async () => {
    await execCommand("using user ES256 did2");
  });

  describe.each([
    ["CTWalletCrossInTime", "ct_wallet_cross_in_time", "inTime"],
    ["CTWalletCrossDeferred", "ct_wallet_cross_deferred", "deferred"],
    [
      "CTWalletCrossPreAuthorised",
      "ct_wallet_cross_pre_authorised",
      "preAuthorised",
    ],
    ["CTWalletSameInTime", "ct_wallet_same_in_time", "inTime"],
    ["CTWalletSameDeferred", "ct_wallet_same_deferred", "deferred"],
    [
      "CTWalletSamePreAuthorised",
      "ct_wallet_same_pre_authorised",
      "preAuthorised",
    ],
  ])("request credential", (type, checkType, communicationType) => {
    it(`should request a credential for ${type}`, async () => {
      expect.assertions(2);

      const credential = await execCommand<string>(
        `conformance holder ${type} ${communicationType}`
      );
      expect(credential).toStrictEqual(expect.any(String));
      credentials.push(credential);

      const check = await execCommand(`conformance check ${checkType}`);
      expect(check).toStrictEqual({ success: true });
    });
  });

  it("should request a credential for CTWalletQualificationCredential", async () => {
    expect.assertions(2);
    const credential = await execCommand<string>(
      `conformance holder CTWalletQualificationCredential inTime ES256 ${JSON.stringify(
        credentials
      )}`
    );
    expect(credential).toStrictEqual(expect.any(String));

    const check = await execCommand(
      "conformance check request_ct_wallet_qualification_credential"
    );
    expect(check).toStrictEqual({ success: true });
  });
});
