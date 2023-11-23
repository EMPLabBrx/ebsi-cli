import { describe, it, expect, vi, beforeAll } from "vitest";
import { execCommand } from "../../src/app.js";

const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

describe("Holder Wallet", () => {
  beforeAll(async () => {
    await execCommand("using user ES256 did2");
  });

  it("should request a credential for PDA1", async () => {
    expect.assertions(1);
    const credential = await execCommand<string>(
      "conformance-new holder VerifiablePortableDocumentA1 deferred"
    );
    expect(credential).toStrictEqual(expect.any(String));
  });
});
