import { describe, it, expect, vi, beforeAll } from "vitest";
import { decodeJwt } from "jose";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import ebsiExtended from "../utils/ebsi-extended.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const { user1, np } = config.vitest;

// There is no Conformance API on Pilot, then this is skipped
const describeSkipPilot = config.env === "pilot" ? describe.skip : describe;

describeSkipPilot("Conformance (e2e)", () => {
  describe.each(["legal-entity", "natural-person"])("%s", (typeUser) => {
    beforeAll(async () => {
      await execCommand("using user null");
      if (typeUser === "legal-entity") {
        await execCommand(
          `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
        );
        await execCommand("myToken: authorisation-old siop");
      } else {
        await execCommand(
          `using user ES256K did2 ${Buffer.from(
            np.ES256K.privateKeyBase64,
            "base64"
          ).toString()}`
        );
        await execCommand(
          `myToken: authorisation-old siop ES256K ${np.ES256K.vcJwt}`
        );
      }
      await execCommand("using token myToken");
    });

    it("should run conformance v2 flow", async () => {
      expect.assertions(9);
      vi.resetAllMocks();

      // issuer mock: initiate
      let response = await execCommand(`conformance-old issuerInitiate`);
      expect(response).toStrictEqual({
        credential_type: expect.any(String) as string,
        issuer: expect.any(String) as string,
      });
      const { credential_type: credentialType, issuer: issuerUrl } =
        response as {
          credential_type: string;
          issuer: string;
        };

      // issuer mock: authorize
      response = await execCommand(
        `conformance-old issuerAuthorize http://localhost:3000 ${credentialType}`
      );
      expect(response).toStrictEqual({
        state: expect.any(String) as string,
        code: expect.any(String) as string,
      });
      const { code } = response as { code: string };

      // issuer mock: token
      response = await execCommand(`conformance-old issuerToken ${code}`);
      expect(response).toStrictEqual({
        token_type: "Bearer",
        access_token: expect.any(String) as string,
        expires_in: expect.any(Number) as number,
        c_nonce: expect.any(String) as string,
        id_token: expect.any(String) as string,
      });
      const { access_token: accessToken, c_nonce: cNonce } = response as {
        access_token: string;
        c_nonce: string;
      };

      // issuer mock: credential
      response = await execCommand(
        `conformance-old issuerCredential ${cNonce} ${accessToken} ES256K ${credentialType} ${issuerUrl}`
      );
      expect(response).toStrictEqual({
        format: "jwt_vc",
        credential: expect.any(String) as string,
        c_nonce: expect.any(String) as string,
        c_nonce_expires_in: expect.any(Number) as number,
      });

      // verifier mock: authentication request
      const { credential: jwtVc } = response as { credential: string };
      response = await execCommand(`conformance-old verifierAuthRequest`);
      expect(response).toStrictEqual(
        expect.objectContaining({
          scope: "openid",
          response_type: "id_token",
          client_id: expect.any(String) as string,
          redirect_uri: expect.any(String) as string,
          claims: expect.any(String) as string,
          nonce: expect.any(String) as string,
        })
      );
      const { claims } = response as { claims: string };
      expect(claims).toBeJsonString();
      expect(JSON.parse(claims)).toStrictEqual({
        id_token: { email: null },
        vp_token: {
          presentation_definition: {
            id: "conformance_mock_vp_request",
            input_descriptors: [
              {
                id: "conformance_mock_vp",
                name: "Conformance Mock VP",
                purpose: "Only accept a VP containing a Conformance Mock VA",
                constraints: {
                  fields: [
                    {
                      path: ["$.vc.credentialSchema"],
                      filter: {
                        allOf: [
                          {
                            type: "array",
                            contains: {
                              type: "object",
                              properties: {
                                id: {
                                  type: "string",
                                  pattern: expect.any(String) as string,
                                },
                              },
                              required: ["id"],
                            },
                          },
                        ],
                      },
                    },
                  ],
                },
              },
            ],
            format: { jwt_vp: { alg: ["ES256K"] } },
          },
        },
      });

      const vcDecoded = decodeJwt(jwtVc);
      const jwtVp: string = await execCommand(
        `compute createPresentationJwt ${jwtVc} ES256K ${vcDecoded.iss}`
      );
      expect(typeof jwtVp).toBe("string");

      // verifier mock: authentication response
      response = await execCommand(
        `conformance-old verifierAuthResponse ${jwtVp}`
      );
      expect(response).toStrictEqual({
        result: true,
        validations: {
          vpFormat: { status: true },
          presentation: { status: true },
          credential: { status: true },
        },
      });
    });
  });
});
