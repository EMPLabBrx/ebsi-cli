import { describe, it, expect, vi, beforeAll } from "vitest";
import { execCommand } from "../../src/app.js";
import { Client } from "../../src/utils/index.js";

const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

describe("Issue to Holder", () => {
  let preAuthorizedInTimeCode: string;
  let preAuthorizedDeferredCode: string;
  let userPin: string;
  beforeAll(async () => {
    await execCommand("using user ES256 did2");
    await execCommand("set user.issuerState issuer-state");
    await execCommand("conformance-new clientMockInitiate");

    await execCommand("jwks: conformance-new get /issuer-mock/jwks");
    const issuerMockDidNP = await execCommand<string>(
      "compute did2 jwks.keys.0"
    );

    const user = await execCommand<Client>("view user");
    if (!user.keys.ES256) throw new Error("No ES256 key defined");

    const preAuthHeaders = {
      kid: user.keys.ES256.id,
    };
    const preAuthInTimePayload = {
      iss: user.clientId,
      sub: issuerMockDidNP,
      client_id: issuerMockDidNP,
      authorization_details: [
        {
          type: "openid_credential",
          format: "jwt_vc",
          types: [
            "VerifiableCredential",
            "VerifiableAttestation",
            "CTWalletSamePreAuthorisedInTime",
          ],
          locations: [user.clientId],
        },
      ],
    };
    preAuthorizedInTimeCode = await execCommand<string>(
      `compute signJwt ${JSON.stringify(
        preAuthInTimePayload
      )} ES256 ${JSON.stringify(preAuthHeaders)}`
    );
    const preAuthDeferredPayload = {
      iss: user.clientId,
      sub: issuerMockDidNP,
      client_id: issuerMockDidNP,
      authorization_details: [
        {
          type: "openid_credential",
          format: "jwt_vc",
          types: [
            "VerifiableCredential",
            "VerifiableAttestation",
            "CTWalletSamePreAuthorisedDeferred",
          ],
          locations: [user.clientId],
        },
      ],
    };
    preAuthorizedDeferredCode = await execCommand<string>(
      `compute signJwt ${JSON.stringify(
        preAuthDeferredPayload
      )} ES256 ${JSON.stringify(preAuthHeaders)}`
    );
    userPin = await execCommand<string>(`compute userPin ${issuerMockDidNP}`);
  });

  describe.each([
    "issue_to_holder_initiate_ct_wallet_same_authorised_in_time",
    "issue_to_holder_validate_ct_wallet_same_authorised_in_time",
    "issue_to_holder_initiate_ct_wallet_same_authorised_deferred",
    "issue_to_holder_validate_ct_wallet_same_authorised_deferred",
    "issue_to_holder_initiate_ct_wallet_same_pre_authorised_in_time",
    "issue_to_holder_validate_ct_wallet_same_pre_authorised_in_time",
    "issue_to_holder_initiate_ct_wallet_same_pre_authorised_deferred",
    "issue_to_holder_validate_ct_wallet_same_pre_authorised_deferred",
  ])("verify test", (type) => {
    it(`should perform ${type}`, async () => {
      expect.assertions(1);

      let extraParams = "";
      if (type.endsWith("pre_authorised_in_time"))
        extraParams = `${preAuthorizedInTimeCode} ${userPin}`;
      if (type.endsWith("pre_authorised_deferred"))
        extraParams = `${preAuthorizedDeferredCode} ${userPin}`;

      const check = await execCommand(
        `conformance-new check ${type} ${extraParams}`
      );
      expect(check).toStrictEqual({ success: true });
    });
  });

  it("should request a CTIssueQualificationCredential", async () => {
    expect.assertions(2);
    await execCommand("compute wait 11");
    const credential = await execCommand(
      "conformance-new holder CTIssueQualificationCredential authorisedInTime ES256 empty skip-credential-offer"
    );
    expect(credential).toStrictEqual(expect.any(String));

    const check = await execCommand(
      "conformance-new check request_ct_issue_to_holder_qualification_credential"
    );
    expect(check).toStrictEqual({ success: true });
  });
});
