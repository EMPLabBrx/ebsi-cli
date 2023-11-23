import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto from "node:crypto";
import { loadConfig } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import { expectStatus } from "../utils/api-get-jest.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import {
  expectPostStatus,
  expectStorageCollection,
} from "../utils/api-post-jest.js";
import { consoleOutput } from "../utils/utils.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, user2, np } = config.vitest;

describe("Notifications (e2e)", () => {
  let notificationIdLE2LE: string;
  let notificationIdLE2NP: string;
  let notificationIdNP2LE: string;
  let notificationIdNP2NP: string;
  const payload = { data: crypto.randomBytes(32).toString("hex") };

  const loadUser2 = async () => {
    await execCommand("using user null");
    await execCommand(
      `using user ES256K did1 ${user2.privateKey} ${user2.did} ${user2.keyId}`
    );
  };

  const loadNp1 = async () => {
    await execCommand("using user null");
    await execCommand(
      `using user ES256K did2 ${Buffer.from(
        np.ES256K.privateKeyBase64,
        "base64"
      ).toString()} ${np.ES256K.did}`
    );
  };

  const loadNp2 = async () => {
    await execCommand("using user null");
    await execCommand(
      `using user EdDSA did2 ${Buffer.from(
        np.EdDSA.privateKeyBase64,
        "base64"
      ).toString()} ${np.EdDSA.did}`
    );
  };

  beforeAll(async () => {
    // siop session for user1
    await execCommand(
      `using user ES256K did1 ${user1.privateKey} ${user1.did} ${user1.keyId}`
    );
    await execCommand("tokenUser1: authorisation-old siop");

    await loadNp1();
    await execCommand(
      `tokenNp1: authorisation-old siop ES256K ${np.ES256K.vcJwt}`
    );

    if (writeOpsEnabled) {
      await loadUser2();
      await execCommand("tokenUser2: authorisation-old siop");

      await loadNp2();
      await execCommand(
        `tokenNp2: authorisation-old siop EdDSA ${np.EdDSA.vcJwt}`
      );
    }
  });

  it("should get a collection of notifications - legal entity", async () => {
    expect.assertions(2);
    await execCommand("using token tokenUser1");
    vi.resetAllMocks();
    await execCommand("notifications get /notifications");
    expectStorageCollection(mockConsole);
  });

  it("should get a collection of notifications - natural person", async () => {
    expect.assertions(2);
    await execCommand("using token tokenNp1");
    vi.resetAllMocks();
    await execCommand("notifications get /notifications");
    expectStorageCollection(mockConsole);
  });

  describeWriteOps("create, get, and delete", () => {
    it("should create a notification from legal entity to legal entity", async () => {
      expect.assertions(1);
      await loadUser2();
      await execCommand("using token tokenUser2");
      vi.resetAllMocks();
      await execCommand(
        `notifications insert ${user1.did} ${JSON.stringify(payload)}`
      );
      expectPostStatus(mockConsole, 201);
      notificationIdLE2LE = consoleOutput(mockConsole, -1);
    });

    it("should create a notification from legal entity to natural person", async () => {
      expect.assertions(1);
      await loadUser2();
      await execCommand("using token tokenUser2");
      vi.resetAllMocks();
      await execCommand(
        `notifications insert ${np.ES256K.did} ${JSON.stringify(payload)}`
      );
      expectPostStatus(mockConsole, 201);
      notificationIdLE2NP = consoleOutput(mockConsole, -1);
    });

    it("should create a notification from natural person to legal entity", async () => {
      expect.assertions(1);
      await loadNp2();
      await execCommand("using token tokenNp2");
      vi.resetAllMocks();
      await execCommand(
        `notifications insert ${user1.did} ${JSON.stringify(payload)}`
      );
      expectPostStatus(mockConsole, 201);
      notificationIdNP2LE = consoleOutput(mockConsole, -1);
    });

    it("should create a notification from natural person to natural person", async () => {
      expect.assertions(1);
      await loadNp2();
      await execCommand("using token tokenNp2");
      vi.resetAllMocks();
      await execCommand(
        `notifications insert ${np.ES256K.did} ${JSON.stringify(payload)}`
      );
      expectPostStatus(mockConsole, 201);
      notificationIdNP2NP = consoleOutput(mockConsole, -1);
    });

    it("should get a notification from legal entity to legal entity", async () => {
      expect.assertions(2);
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand(
        `notifications get /notifications/${notificationIdLE2LE}`
      );
      const notification = consoleOutput(mockConsole, -1);
      expectStatus(mockConsole, 200);
      expect(notification).toStrictEqual(
        expect.objectContaining({
          from: user2.did,
          to: user1.did,
          payload,
        })
      );
    });

    it("should get a notification from legal entity to natural person", async () => {
      expect.assertions(2);
      await execCommand("using token tokenNp1");
      vi.resetAllMocks();
      await execCommand(
        `notifications get /notifications/${notificationIdLE2NP}`
      );
      const notification = consoleOutput(mockConsole, -1);
      expectStatus(mockConsole, 200);
      expect(notification).toStrictEqual(
        expect.objectContaining({
          from: user2.did,
          to: np.ES256K.did,
          payload,
        })
      );
    });

    it("should get a notification from natural person to legal entity", async () => {
      expect.assertions(2);
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand(
        `notifications get /notifications/${notificationIdNP2LE}`
      );
      const notification = consoleOutput(mockConsole, -1);
      expectStatus(mockConsole, 200);
      expect(notification).toStrictEqual(
        expect.objectContaining({
          from: np.EdDSA.did,
          to: user1.did,
          payload,
        })
      );
    });

    it("should get a notification from natural person to natural person", async () => {
      expect.assertions(2);
      await execCommand("using token tokenNp1");
      vi.resetAllMocks();
      await execCommand(
        `notifications get /notifications/${notificationIdNP2NP}`
      );
      const notification = consoleOutput(mockConsole, -1);
      expectStatus(mockConsole, 200);
      expect(notification).toStrictEqual(
        expect.objectContaining({
          from: np.EdDSA.did,
          to: np.ES256K.did,
          payload,
        })
      );
    });

    it("should reject unauthorized access to a notification", async () => {
      expect.assertions(3);
      await execCommand("using token tokenUser2");
      vi.resetAllMocks();
      await expect(
        execCommand(`notifications get /notifications/${notificationIdLE2LE}`)
      ).rejects.toThrow();
      const error = consoleOutput(mockConsole, -1);
      expect(error).toStrictEqual({
        title: "Forbidden",
        status: 403,
        detail: `The notification was not sent to ${user2.did}`,
        type: "about:blank",
      });
      expectStatus(mockConsole, 403);
    });

    it("should reject unauthorized access to delete a notification", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand("using token tokenUser2");
      vi.resetAllMocks();
      await expect(
        execCommand(`notifications delete ${notificationIdLE2LE}`)
      ).rejects.toThrow();
      const error = consoleOutput(mockConsole, -1);
      expect(error).toStrictEqual({
        title: "Forbidden",
        status: 403,
        detail: `The notification was not sent to ${user2.did}`,
        type: "about:blank",
      });
      expectStatus(mockConsole, 403);
    });

    it("should delete a notification", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand("using token tokenUser1");
      vi.resetAllMocks();
      await execCommand(`notifications delete ${notificationIdLE2LE}`);
      expectStatus(mockConsole, 204);
      vi.resetAllMocks();
      await expect(
        execCommand(`notifications get /notifications/${notificationIdLE2LE}`)
      ).rejects.toThrow();
      expectStatus(mockConsole, 404);
    });
  });
});
