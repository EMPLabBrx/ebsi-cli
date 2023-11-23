import { describe, it, expect, vi, beforeAll, beforeEach } from "vitest";
import ebsiExtended from "../utils/ebsi-extended.js";
import { execCommand } from "../../src/app.js";
import { generateTokenWebAppOnboarding } from "../utils/onboarding.js";
import { Client } from "../../src/utils/Client.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

describe("Users Onboarding (e2e)", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe.each(["ES256K", "ES256", "RS256", "EdDSA"])("alg %s", (alg) => {
    let tokenCaptcha: string;
    beforeAll(async () => {
      tokenCaptcha = await generateTokenWebAppOnboarding();
      await execCommand(`using token ${tokenCaptcha}`);
    });

    describe.each(["did1", "did2"])("did method %s", (didMethod) => {
      it(`should support the full SIOP flow for an unknown user using alg ${alg} - ${
        didMethod === "did1" ? "legal entity" : "natural person"
      }`, async () => {
        expect.assertions(1);
        await execCommand("using user null");
        await execCommand<Client>(`using user ${alg} ${didMethod}`);
        vi.resetAllMocks();
        const command = `onboarding authentication ${alg}`;
        if (alg === "RS256") {
          // RSA not supported in verifiable presentations for natural persons
          await expect(execCommand(command)).rejects.toThrow(
            "getKeyPairForKtyAndCrv does not support: RSA and undefined"
          );
        } else {
          const token = await execCommand(command);
          expect(token).toBeJwt();
        }
      });
    });
  });
});
