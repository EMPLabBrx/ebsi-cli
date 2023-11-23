import { describe, it, expect, vi, beforeAll } from "vitest";
import { execCommand } from "../../src/app.js";

const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

describe("Verifier", () => {
  beforeAll(async () => {
    await execCommand("using user ES256");
    await execCommand("conformance-new clientMockInitiate");
  });

  describe.each([
    "verifier_id_token_exchange",
    "verifier_vp_valid_vc",
    "verifier_vp_expired_vc",
    "verifier_vp_revoked_vc",
    "verifier_vp_not_yet_valid_vc",
  ])("verify test", (type) => {
    it(`should verify request ${type}`, async () => {
      expect.assertions(1);

      const check = await execCommand(`conformance-new check ${type}`);
      expect(check).toStrictEqual({ success: true });
    });
  });
});
