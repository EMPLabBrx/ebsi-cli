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
    [
      "CTWalletCrossAuthorisedInTime",
      "ct_wallet_cross_authorised_in_time",
      "authorisedInTime",
    ],
    [
      "CTWalletCrossAuthorisedDeferred",
      "ct_wallet_cross_authorised_deferred",
      "authorisedDeferred",
    ],
    [
      "CTWalletCrossPreAuthorisedInTime",
      "ct_wallet_cross_pre_authorised_in_time",
      "preAuthorisedInTime",
    ],
    [
      "CTWalletCrossPreAuthorisedDeferred",
      "ct_wallet_cross_pre_authorised_deferred",
      "preAuthorisedDeferred",
    ],
    [
      "CTWalletSameAuthorisedInTime",
      "ct_wallet_same_authorised_in_time",
      "authorisedInTime",
    ],
    [
      "CTWalletSameAuthorisedDeferred",
      "ct_wallet_same_authorised_deferred",
      "authorisedDeferred",
    ],
    [
      "CTWalletSamePreAuthorisedInTime",
      "ct_wallet_same_pre_authorised_in_time",
      "preAuthorisedInTime",
    ],
    [
      "CTWalletSamePreAuthorisedDeferred",
      "ct_wallet_same_pre_authorised_deferred",
      "preAuthorisedDeferred",
    ],
  ])("request credential", (type, checkType, communicationType) => {
    it(`should request a credential for ${type}`, async () => {
      expect.assertions(2);

      const credential = await execCommand<string>(
        `conformance-new holder ${type} ${communicationType}`
      );
      expect(credential).toStrictEqual(expect.any(String));
      credentials.push(credential);

      const check = await execCommand(`conformance-new check ${checkType}`);
      expect(check).toStrictEqual({ success: true });
    });
  });

  it("should request a credential for CTWalletQualificationCredential", async () => {
    expect.assertions(2);
    const credential = await execCommand<string>(
      `conformance-new holder CTWalletQualificationCredential authorisedInTime ES256 ${JSON.stringify(
        credentials
      )}`
    );
    expect(credential).toStrictEqual(expect.any(String));

    const check = await execCommand(
      "conformance-new check request_ct_wallet_qualification_credential"
    );
    expect(check).toStrictEqual({ success: true });
  });
});
