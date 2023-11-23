import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto from "node:crypto";
import { ethers } from "ethers";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { loadConfig, UserDetails } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import { PaginatedList } from "../../src/interfaces/index.js";

const { sha256 } = ethers.utils;

const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { issuer1, admin } = config.vitestNew;

const newRootTAO = {
  did: EbsiWallet.createDid(),
  privateKey: crypto.randomBytes(32).toString("hex"),
  accreditation: {
    vc: "",
    url: "",
    id: "",
  },
};

const newTAO = {
  did: EbsiWallet.createDid(),
  privateKey: crypto.randomBytes(32).toString("hex"),
  accreditation: {
    vc: "",
    url: "",
    id: "",
  },
};

const newTI = {
  did: EbsiWallet.createDid(),
  privateKey: crypto.randomBytes(32).toString("hex"),
  accreditation: {
    vc: "",
    url: "",
    id: "",
  },
};

async function loadUser(user: UserDetails, tokenName?: string): Promise<void> {
  await execCommand("using user null");
  await execCommand(
    `using user ES256K did1 ${user.privateKey} ${user.did} ${user.keyId ?? ""}`
  );
  await execCommand(`using user ES256 did1 ${user.privateKey} ${user.did}`);
  if (tokenName) await execCommand(`using token ${tokenName}`);
}

describe("Trusted Issuers Registry (e2e)", () => {
  describe("GET /issuers", () => {
    let attributeId: string;
    it("should get a collection of issuers", async () => {
      expect.assertions(1);
      const response = await execCommand("tir-new get /issuers");
      expect(response).toStrictEqual({
        self: expect.any(String) as string,
        items: expect.arrayContaining([]) as unknown[],
        total: expect.any(Number) as number,
        pageSize: expect.any(Number) as number,
        links: {
          first: expect.any(String) as string,
          prev: expect.any(String) as string,
          next: expect.any(String) as string,
          last: expect.any(String) as string,
        },
      });
    });

    it("should get an issuer", async () => {
      expect.assertions(1);
      const response = await execCommand(`tir-new get /issuers/${issuer1.did}`);
      expect(response).toStrictEqual({
        did: issuer1.did,
        attributes: expect.arrayContaining([
          {
            hash: expect.any(String) as string,
            body: expect.any(String) as string,
            tao: expect.any(String) as string,
            rootTao: expect.any(String) as string,
            issuerType: expect.any(String) as string,
          },
        ]) as unknown[],
      });
    });

    it("should get the attributes of an issuer", async () => {
      expect.assertions(1);
      const response = await execCommand<PaginatedList<{ id: string }>>(
        `tir-new get /issuers/${issuer1.did}/attributes`
      );
      expect(response).toStrictEqual({
        self: expect.any(String) as string,
        items: expect.arrayContaining([]) as unknown[],
        total: expect.any(Number) as number,
        pageSize: expect.any(Number) as number,
        links: {
          first: expect.any(String) as string,
          prev: expect.any(String) as string,
          next: expect.any(String) as string,
          last: expect.any(String) as string,
        },
      });
      attributeId = response.items[0].id;
    });

    it("should get an attribute from an issuer", async () => {
      expect.assertions(1);
      const response = await execCommand(
        `tir-new get /issuers/${issuer1.did}/attributes/${attributeId}`
      );
      expect(response).toStrictEqual({
        did: issuer1.did,
        attribute: {
          hash: expect.any(String) as string,
          body: expect.any(String) as string,
          tao: expect.any(String) as string,
          rootTao: expect.any(String) as string,
          issuerType: expect.any(String) as string,
        },
      });
    });

    it("should get revisions collection from an attribute of an issuer", async () => {
      expect.assertions(1);
      const response = await execCommand(
        `tir-new get /issuers/${issuer1.did}/attributes/${attributeId}/revisions`
      );
      expect(response).toStrictEqual({
        self: expect.any(String) as string,
        items: expect.arrayContaining([]) as unknown[],
        total: expect.any(Number) as number,
        pageSize: expect.any(Number) as number,
        links: {
          first: expect.any(String) as string,
          prev: expect.any(String) as string,
          next: expect.any(String) as string,
          last: expect.any(String) as string,
        },
      });
    });
  });

  describeWriteOps("POST /jsonrpc", () => {
    async function issueOnboardingCredential(newDid: string) {
      const payloadVcOnboard = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        type: [
          "VerifiableCredential",
          "VerifiableAttestation",
          "VerifiableAuthorisationToOnboard",
        ],
        issuer: issuer1.did,
        credentialSubject: {
          id: newDid,
          accreditedFor: [],
        },
        termsOfUse: {
          id: issuer1.accreditation,
          type: "IssuanceCertificate",
        },
        credentialSchema: {
          id: `${config.domain}/trusted-schemas-registry/v3/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM`,
          type: "FullJsonSchemaValidator2021",
        },
      };
      await loadUser(issuer1);
      return execCommand<string>(
        `compute createVcJwt ${JSON.stringify(payloadVcOnboard)} {} ES256K`
      );
    }

    beforeAll(async () => {
      await execCommand(`set domain ${config.domain}`);

      // session for the admin
      await loadUser(admin);
      await execCommand("res: authorisation-new auth tir_write_presentation");
      await execCommand("set tokenAdmin res.access_token");

      // session for issuer1
      await loadUser(issuer1);
      await execCommand("res: authorisation-new auth tir_write_presentation");
      await execCommand("set tokenIssuer res.access_token");

      // Register RootTAO in the DID Registry
      let vcToOnboard = await issueOnboardingCredential(newRootTAO.did);
      await loadUser(newRootTAO);
      await execCommand(
        `run new/registerDidDocument_ES256K_ES256 ${vcToOnboard}`
      );

      // Register TAO in the DID Registry
      vcToOnboard = await issueOnboardingCredential(newTAO.did);
      await loadUser(newTAO);
      await execCommand(
        `run new/registerDidDocument_ES256K_ES256 ${vcToOnboard}`
      );

      // Register TI1 in the DID Registry
      vcToOnboard = await issueOnboardingCredential(newTI.did);
      await loadUser(newTI);
      await execCommand(
        `run new/registerDidDocument_ES256K_ES256 ${vcToOnboard}`
      );
    });

    it("should reject the registration of a RootTAO by unauthorized users", async () => {
      expect.assertions(1);
      await loadUser(issuer1, "tokenIssuer");
      const attributeId = await execCommand<string>("compute randomID");
      await expect(
        execCommand(
          `tir-new setAttributeMetadata ${newRootTAO.did} ${attributeId} roottao`
        )
      ).rejects.toThrow(
        "Transaction failed: Status 0x0. Revert reason: Policy error: sender doesn't have the attribute TIR:setAttributeMetadata"
      );
    });

    it("should register a new RootTAO", async () => {
      expect.assertions(2);
      await loadUser(admin, "tokenAdmin");

      newRootTAO.accreditation.id = await execCommand<string>(
        "compute randomID"
      );
      newRootTAO.accreditation.vc = await execCommand<string>(
        `run new/issue_VerifiableAuthorisationForTrustChain ${admin.did} ${newRootTAO.did} ${admin.accreditation} ${newRootTAO.accreditation.id}`
      );
      newRootTAO.accreditation.url = `${config.domain}/trusted-issuers-registry/v5/issuers/${newRootTAO.did}/attributes/${newRootTAO.accreditation.id}`;
      let response = await execCommand(
        `tir-new setAttributeMetadata ${newRootTAO.did} ${newRootTAO.accreditation.id} roottao`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      await loadUser(newRootTAO);
      await execCommand(
        `res: authorisation-new auth tir_invite_presentation ES256K ${newRootTAO.accreditation.vc}`
      );
      await execCommand("using token res.access_token");

      response = await execCommand(
        `tir-new setAttributeData ${newRootTAO.did} ${newRootTAO.accreditation.id} ${newRootTAO.accreditation.vc}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );
    });

    it("should register a new TAO where the accreditor is a RootTAO", async () => {
      expect.assertions(2);
      await loadUser(newRootTAO);
      await execCommand("res: authorisation-new auth tir_write_presentation");
      await execCommand("using token res.access_token");

      newTAO.accreditation.id = await execCommand<string>("compute randomID");
      newTAO.accreditation.vc = await execCommand<string>(
        `run new/issue_VerifiableAccreditationToAccredit ${newRootTAO.did} ${newTAO.did} ${newRootTAO.accreditation.url} ${newTAO.accreditation.id}`
      );
      newTAO.accreditation.url = `${config.domain}/trusted-issuers-registry/v5/issuers/${newTAO.did}/attributes/${newTAO.accreditation.id}`;

      let response = await execCommand(
        `tir-new setAttributeMetadata ${newTAO.did} ${newTAO.accreditation.id} tao ${newRootTAO.did} ${newRootTAO.accreditation.id}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      await loadUser(newTAO);
      await execCommand(
        `res: authorisation-new auth tir_invite_presentation ES256K ${newTAO.accreditation.vc}`
      );
      await execCommand("using token res.access_token");

      response = await execCommand(
        `tir-new setAttributeData ${newTAO.did} ${newTAO.accreditation.id} ${newTAO.accreditation.vc}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );
    });

    it("should register a new TI where the accreditor is a TAO", async () => {
      expect.assertions(2);
      await loadUser(newTAO);
      await execCommand("res: authorisation-new auth tir_write_presentation");
      await execCommand("using token res.access_token");

      newTI.accreditation.id = await execCommand<string>("compute randomID");
      newTI.accreditation.vc = await execCommand<string>(
        `run new/issue_VerifiableAccreditationToAttest ${newTAO.did} ${newTI.did} ${newTAO.accreditation.url} ${newTI.accreditation.id}`
      );
      newTI.accreditation.url = `${config.domain}/trusted-issuers-registry/v5/issuers/${newTI.did}/attributes/${newTI.accreditation.id}`;

      let response = await execCommand(
        `tir-new setAttributeMetadata ${newTI.did} ${newTI.accreditation.id} ti ${newTAO.did} ${newTAO.accreditation.id}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      await loadUser(newTI);
      await execCommand(
        `res: authorisation-new auth tir_invite_presentation ES256K ${newTI.accreditation.vc}`
      );
      await execCommand("using token res.access_token");

      response = await execCommand(
        `tir-new setAttributeData ${newTI.did} ${newTI.accreditation.id} ${newTI.accreditation.vc}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );
    });

    it("should revoke a credential", async () => {
      expect.assertions(2);
      await loadUser(newTAO, "tokenTao");
      await execCommand(
        "res: authorisation-new auth tir_write_presentation ES256K"
      );
      await execCommand("using token res.access_token");

      let response = await execCommand(
        `tir-new setAttributeMetadata ${newTI.did} ${newTI.accreditation.id} revoked ${newTAO.did} ${newTAO.accreditation.id}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      response = await execCommand(`tir-new get /issuers/${newTI.did}`);
      expect(response).toStrictEqual({
        did: newTI.did,
        attributes: [
          {
            hash: expect.any(String) as string,
            body: "",
            tao: newTAO.did,
            rootTao: newRootTAO.did,
            issuerType: "Revoked",
          },
        ] as unknown[],
      });
    });

    it("should add/update proxy data", async () => {
      expect.assertions(3);
      await loadUser(newTI);

      const proxyObject = {
        prefix: "https://example.net",
        headers: {
          Authorization: `Bearer ${crypto.randomBytes(16).toString("hex")}`,
        },
        testSuffix: "/cred/1",
      };
      const proxyUtf8 = JSON.stringify(proxyObject);
      const proxyId = sha256(Buffer.from(proxyUtf8));

      // as the issuer proxy is not active, this test bypass the API to avoid the validation of the proxy
      let response = await execCommand(
        `proxyledger tir-new addIssuerProxy ${newTI.did} ${proxyUtf8}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      response = await execCommand(
        `tir-new get /issuers/${newTI.did}/proxies/${proxyId}`
      );
      expect(response).toStrictEqual(proxyObject);

      // update issuer proxy
      proxyObject.prefix = "https://example.com";
      response = await execCommand(
        `proxyledger tir-new updateIssuerProxy ${
          newTI.did
        } ${proxyId} ${JSON.stringify(proxyObject)}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );
    });
  });
});
