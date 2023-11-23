import { describe, it, expect, vi, beforeAll } from "vitest";
import { ethers } from "ethers";
import { DIDDocument } from "did-resolver";
import { loadConfig, UserDetails } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import {
  expectCollection,
  expectResponse,
  expectStatus,
} from "../utils/api-get-jest.js";
import ebsiExtended from "../utils/ebsi-extended.js";
import { expectTransaction } from "../utils/jsonrpc-jest.js";
import { Client } from "../../src/utils/Client.js";

expect.extend(ebsiExtended);
const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { user1, issuer1 } = config.vitest;
let newUser: Client;
let didDocument: DIDDocument;
const publicKey2 = ethers.Wallet.createRandom().publicKey;
const publicKey3 = ethers.Wallet.createRandom().publicKey;
let vMethodIdES256: string;
let vMethodIdEdDSA: string;

async function loadUser(user: UserDetails, token?: string): Promise<void> {
  await execCommand("using user null");
  await execCommand(
    `using user ES256K did1 ${user.privateKey} ${user.did} ${user.keyId ?? ""}`
  );
  if (user.jwks && user.jwks.ES256) {
    await execCommand(
      `using user ES256 did1 ${Buffer.from(
        user.jwks.ES256.privateKeyBase64,
        "base64"
      ).toString()} ${user.did} ${user.jwks.ES256.keyId ?? ""}`
    );
  }
  if (token) await execCommand(`using token ${token}`);
}

describe("DID Registry (e2e)", () => {
  let vcToOnboard: string;
  let accessTokenWrite: string;

  beforeAll(async () => {
    if (!writeOpsEnabled) return;
    await execCommand("using user null");
    await execCommand("using user ES256K did1");
    await execCommand("using user ES256 did1");
    newUser = await execCommand("using user EdDSA did1");
    didDocument = newUser.generateDidDocument();
    [, vMethodIdES256] = didDocument.verificationMethod[1].id.split("#");
    [, vMethodIdEdDSA] = didDocument.verificationMethod[2].id.split("#");

    const payloadVcOnboard = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: [
        "VerifiableCredential",
        "VerifiableAttestation",
        "VerifiableAuthorisationToOnboard",
      ],
      issuer: issuer1.did,
      credentialSubject: {
        id: newUser.did,
        accreditedFor: [],
      },
      termsOfUse: {
        id: issuer1.accreditation,
        type: "IssuanceCertificate",
      },
      credentialSchema: {
        id: `${config.domain}/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM`,
        type: "FullJsonSchemaValidator2021",
      },
    };
    await loadUser(issuer1);
    vcToOnboard = await execCommand<string>(
      `compute createVcJwt ${JSON.stringify(payloadVcOnboard)} {} ES256`
    );

    await execCommand("using user null");
    await execCommand(
      `using user ES256K did1 ${newUser.ethWallet.privateKey.slice(2)} ${
        newUser.did
      } ${newUser.keys.ES256K.id}`
    );
  });

  describe("GET /identifiers", () => {
    it("should get a collection of identifiers", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand("did get /identifiers");
      expectCollection<{
        did: string;
        href: string;
      }>(mockConsole);
      expectStatus(mockConsole, 200);
    });

    it("should get a did", async () => {
      expect.assertions(3);
      vi.resetAllMocks();
      await execCommand(`did get /identifiers/${user1.did}`);
      expectResponse(mockConsole, expect.objectContaining({}));
      expectStatus(mockConsole, 200);
    });
  });

  describeWriteOps("POST /jsonrpc", () => {
    const commandsUser = [
      [
        "insertDidDocument",
        () =>
          `${newUser.did} ${JSON.stringify({
            "@context": didDocument["@context"],
          })} ${newUser.ethWallet.publicKey} 2023-01-01 2030-01-01 ${
            didDocument.verificationMethod[0].id.split("#")[1]
          }`,
      ],
      [
        "updateBaseDocument",
        () =>
          `${newUser.did} ${JSON.stringify({
            "@context": didDocument["@context"],
          })}`,
      ],
      ["addController", () => `${newUser.did} ${user1.did}`],
      ["revokeController", () => `${newUser.did} ${user1.did}`],
      ["addVerificationMethod", () => `${newUser.did} ${publicKey2}`],
      [
        "addVerificationMethod",
        () =>
          `${newUser.did} ${JSON.stringify(
            didDocument.verificationMethod[1].publicKeyJwk
          )} ${vMethodIdES256}`,
      ],
      [
        "addVerificationMethod",
        () =>
          `${newUser.did} ${JSON.stringify(
            didDocument.verificationMethod[2].publicKeyJwk
          )} ${vMethodIdEdDSA}`,
      ],
      [
        "addVerificationRelationship",
        () =>
          `${newUser.did} assertionMethod ${vMethodIdES256} 2023-01-01 2030-01-01`,
      ],
      [
        "revokeVerificationMethod",
        () => `${newUser.did} ${vMethodIdES256} 2023-01-03`,
      ],
      [
        "expireVerificationMethod",
        () => `${newUser.did} ${vMethodIdEdDSA} 2030-01-03`,
      ],
      [
        "rollVerificationMethod",
        () => `${newUser.did} ${publicKey3} 2024 2030 ${vMethodIdES256} 3600`,
      ],
    ];

    describe.each(commandsUser)(
      "send transaction for %s",
      (method: string, params: () => string) => {
        it("should work", async () => {
          expect.assertions(7);

          if (method === "insertDidDocument") {
            const result = await execCommand<{ access_token: string }>(
              `authorisation auth didr_invite_presentation ES256K ${vcToOnboard}`
            );
            const accessTokenInvite = result.access_token;
            await execCommand(`using token ${accessTokenInvite}`);
          } else {
            if (!accessTokenWrite) {
              const result = await execCommand<{ access_token: string }>(
                "authorisation auth didr_write_presentation ES256K"
              );
              accessTokenWrite = result.access_token;
            }
            await execCommand(`using token ${accessTokenWrite}`);
          }

          vi.resetAllMocks();
          await execCommand(`did ${method} ${params()}`);
          expectTransaction(mockConsole);
        });
      }
    );
  });
});
