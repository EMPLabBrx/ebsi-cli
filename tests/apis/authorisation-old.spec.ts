import { describe, it, expect, vi, beforeEach } from "vitest";
import { loadConfig } from "../../src/config.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import { execCommand } from "../../src/app.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const { requesterApp, resourceApp, user1, np } = config.vitest;

describe("Authorisation Old (e2e)", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  describe("POST /oauth2-sessions", () => {
    it("should create an OAuth2 session", async () => {
      expect.assertions(1);
      await execCommand(
        `using app ${requesterApp.name} ${requesterApp.privateKey}`
      );
      const token = await execCommand(
        `authorisation-old oauth2 ${resourceApp.name}`
      );
      expect(token).toBeJwt();
    });
  });

  describe.each(["ES256K", "ES256", "RS256", "EdDSA"])(
    "POST /siop-sessions with alg %s",
    (alg) => {
      it("should create a SIOP session for a known user (legal entity)", async () => {
        expect.assertions(1);
        let privateKey: string;
        let keyId: string;
        if (alg === "ES256K") {
          privateKey = user1.privateKey;
          keyId = user1.keyId;
        } else {
          const key = user1.jwks[alg] as {
            privateKeyBase64: string;
            keyId: string;
          };
          privateKey = Buffer.from(key.privateKeyBase64, "base64").toString();
          keyId = key.keyId;
        }

        await execCommand(
          `using user ${alg} did1 ${privateKey} ${user1.did} ${keyId}`
        );

        const token = await execCommand(`authorisation-old siop ${alg}`);
        expect(token).toBeJwt();
      });

      it("should create a SIOP session for a known user (natural person)", async () => {
        expect.assertions(1);
        const jwkString = Buffer.from(
          np[alg].privateKeyBase64,
          "base64"
        ).toString();
        await execCommand(`using user ${alg} did2 ${jwkString} ${np[alg].did}`);
        const command = `authorisation-old siop ${alg} ${np[alg].vcJwt}`;
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
    }
  );
});
