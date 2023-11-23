import { describe, it, expect, vi, beforeAll } from "vitest";
import crypto, { randomBytes } from "crypto";
import { ethers } from "ethers";
import { EbsiWallet } from "@cef-ebsi/wallet-lib";
import { loadConfig, UserDetails } from "../../src/config.js";
import { execCommand } from "../../src/app.js";
import { PaginatedList } from "../../src/interfaces/index.js";
import { removePrefix0x } from "../../src/utils/index.js";

const { sha256 } = ethers.utils;

const mockConsole = vi.spyOn(console, "log");
mockConsole.mockImplementation(() => {});

const config = loadConfig();
const writeOpsEnabled = ["test", "conformance"].includes(config.env);
const describeWriteOps = writeOpsEnabled ? describe : describe.skip;
const { issuer1, admin } = config.vitest;

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

const newTI1 = {
  did: EbsiWallet.createDid(),
  privateKey: crypto.randomBytes(32).toString("hex"),
  accreditation1: {
    vc: "",
    url: "",
    id: "",
  },
  accreditation2: {
    vc: "",
    url: "",
    id: "",
  },
};

const newTI2 = {
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
  if (tokenName) await execCommand(`using token ${tokenName}`);
}

describe("Trusted Issuers Registry (e2e)", () => {
  describe("GET /issuers", () => {
    let attributeId: string;
    it("should get a collection of issuers", async () => {
      expect.assertions(1);
      const response = await execCommand("tir get /issuers");
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
      const response = await execCommand(`tir get /issuers/${issuer1.did}`);
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
        `tir get /issuers/${issuer1.did}/attributes`
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
        `tir get /issuers/${issuer1.did}/attributes/${attributeId}`
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
        `tir get /issuers/${issuer1.did}/attributes/${attributeId}/revisions`
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
          id: `${config.domain}/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM`,
          type: "FullJsonSchemaValidator2021",
        },
      };
      await loadUser(issuer1);
      return execCommand<string>(
        `compute createVcJwt ${JSON.stringify(payloadVcOnboard)} {} ES256K`
      );
    }

    beforeAll(async () => {
      // session for the admin
      await loadUser(admin);
      await execCommand("res: authorisation auth tir_write_presentation");
      await execCommand("set tokenAdmin res.access_token");

      // session for issuer1
      await loadUser(issuer1);
      await execCommand("res: authorisation auth tir_write_presentation");
      await execCommand("set tokenIssuer res.access_token");

      // Register RootTAO in the DID Registry
      let vcToOnboard = await issueOnboardingCredential(newRootTAO.did);
      await loadUser(newRootTAO);
      await execCommand(
        `res: authorisation auth didr_invite_presentation ES256K ${vcToOnboard}`
      );
      await execCommand("using token res.access_token");
      await execCommand("did insertDidDocument");

      // Register TAO in the DID Registry
      vcToOnboard = await issueOnboardingCredential(newTAO.did);
      await loadUser(newTAO);
      await execCommand(
        `res: authorisation auth didr_invite_presentation ES256K ${vcToOnboard}`
      );
      await execCommand("using token res.access_token");
      await execCommand("did insertDidDocument");

      // This TAO is used in the invite + acceptance flow, then it needs
      // assertionMethod relationship to be able to verify the credential
      // in the "invite" part
      await execCommand(
        `res: authorisation auth didr_write_presentation ES256K`
      );
      await execCommand("using token res.access_token");
      await execCommand(
        "did addVerificationRelationship user.did assertionMethod ES256K"
      );

      // Register TI1 in the DID Registry
      vcToOnboard = await issueOnboardingCredential(newTI1.did);
      await loadUser(newTI1);
      await execCommand(
        `res: authorisation auth didr_invite_presentation ES256K ${vcToOnboard}`
      );
      await execCommand("using token res.access_token");
      await execCommand("did insertDidDocument");

      // Register TI2 in the DID Registry
      vcToOnboard = await issueOnboardingCredential(newTI2.did);
      await loadUser(newTI2);
      await execCommand(
        `res: authorisation auth didr_invite_presentation ES256K ${vcToOnboard}`
      );
      await execCommand("using token res.access_token");
      await execCommand("did insertDidDocument");
    });

    // Register flow

    it("should reject the registration of a RootTAO by unauthorized users", async () => {
      expect.assertions(1);
      await loadUser(issuer1, "tokenIssuer");
      await execCommand(
        `payloadVcRootTAO: load scripts/assets/VerifiableAuthorisationForTrustChain.json`
      );
      await execCommand(`set payloadVcRootTAO.issuer ${issuer1.did}`);
      await execCommand(
        `set payloadVcRootTAO.credentialSubject.id ${newRootTAO.did}`
      );
      await execCommand(
        `set payloadVcRootTAO.credentialSchema.id ${config.domain}/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM`
      );
      await execCommand(
        `set payloadVcRootTAO.termsOfUse.id ${issuer1.accreditation}`
      );
      const badVC = await execCommand<string>(
        `compute createVcJwt payloadVcRootTAO {} ES256K`
      );
      await expect(
        execCommand(`tir insertIssuer ${newRootTAO.did} ${badVC} roottao`)
      ).rejects.toThrow(
        "Transaction failed: Status 0x0. Revert reason: Policy error: sender doesn't have the attribute TIR:insertIssuer"
      );
    });

    it("should register a new RootTAO", async () => {
      expect.assertions(1);
      await loadUser(admin, "tokenAdmin");
      await execCommand(
        `payloadVcRootTAO: load scripts/assets/VerifiableAuthorisationForTrustChain.json`
      );
      await execCommand(`set payloadVcRootTAO.issuer ${admin.did}`);
      await execCommand(
        `set payloadVcRootTAO.credentialSubject.id ${newRootTAO.did}`
      );
      await execCommand(
        `set payloadVcRootTAO.credentialSchema.id ${config.domain}/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM`
      );
      await execCommand(
        `set payloadVcRootTAO.termsOfUse.id ${admin.accreditation}`
      );
      newRootTAO.accreditation.vc = await execCommand<string>(
        `compute createVcJwt payloadVcRootTAO {} ES256K`
      );
      newRootTAO.accreditation.id = removePrefix0x(
        sha256(Buffer.from(newRootTAO.accreditation.vc))
      );
      newRootTAO.accreditation.url = `${config.domain}/trusted-issuers-registry/v4/issuers/${newRootTAO.did}/attributes/${newRootTAO.accreditation.id}`;
      const response = await execCommand(
        `tir insertIssuer ${newRootTAO.did} ${newRootTAO.accreditation.vc} roottao`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );
    });

    it("should register a new TAO where the accreditor is a RootTAO", async () => {
      expect.assertions(1);
      await loadUser(newRootTAO);
      await execCommand("res: authorisation auth tir_write_presentation");
      await execCommand("using token res.access_token");
      await execCommand(
        `payloadVcTAO: load scripts/assets/VerifiableAccreditationToAccredit.json`
      );
      await execCommand(`set payloadVcTAO.issuer ${newRootTAO.did}`);
      await execCommand(`set payloadVcTAO.credentialSubject.id ${newTAO.did}`);
      await execCommand(
        `set payloadVcTAO.credentialSchema.id ${config.domain}/trusted-schemas-registry/v2/schemas/zjVFNvbEBPAr3a724DttioZpgZmNr75BBtRzZqk7pkDe`
      );
      await execCommand(
        `set payloadVcTAO.termsOfUse.id ${newRootTAO.accreditation.url}`
      );
      newTAO.accreditation.vc = await execCommand<string>(
        `compute createVcJwt payloadVcTAO {} ES256K`
      );
      newTAO.accreditation.id = removePrefix0x(
        sha256(Buffer.from(newTAO.accreditation.vc))
      );
      newTAO.accreditation.url = `${config.domain}/trusted-issuers-registry/v4/issuers/${newTAO.did}/attributes/${newTAO.accreditation.id}`;

      const response = await execCommand(
        `tir insertIssuer ${newTAO.did} ${newTAO.accreditation.vc} tao ${newRootTAO.did} ${newRootTAO.accreditation.id}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );
    });

    it("should register a new TI where the accreditor is a TAO", async () => {
      expect.assertions(1);
      await loadUser(newTAO);
      await execCommand("res: authorisation auth tir_write_presentation");
      await execCommand("set tokenTao res.access_token");
      await execCommand("using token tokenTao");
      await execCommand(
        `payloadVcTI: load scripts/assets/VerifiableAccreditationToAttest.json`
      );
      await execCommand(`set payloadVcTI.issuer ${newTAO.did}`);
      await execCommand(`set payloadVcTI.credentialSubject.id ${newTI1.did}`);
      await execCommand(
        `set payloadVcTI.credentialSchema.id ${config.domain}/trusted-schemas-registry/v2/schemas/zjVFNvbEBPAr3a724DttioZpgZmNr75BBtRzZqk7pkDe`
      );
      await execCommand(
        `set payloadVcTI.termsOfUse.id ${newTAO.accreditation.url}`
      );
      newTI1.accreditation1.vc = await execCommand<string>(
        `compute createVcJwt payloadVcTI {} ES256K`
      );
      newTI1.accreditation1.id = removePrefix0x(
        sha256(Buffer.from(newTI1.accreditation1.vc))
      );
      newTI1.accreditation1.url = `${config.domain}/trusted-issuers-registry/v4/issuers/${newTI1.did}/attributes/${newTI1.accreditation1.id}`;

      const response = await execCommand(
        `tir insertIssuer ${newTI1.did} ${newTI1.accreditation1.vc} ti ${newTAO.did} ${newTAO.accreditation.id}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );
    });

    it("should register a credential in an existing issuer", async () => {
      expect.assertions(2);
      await loadUser(newTAO, "tokenTao");
      await execCommand(
        `payloadVcTI: load scripts/assets/VerifiableAccreditationToAttest.json`
      );
      await execCommand(`set payloadVcTI.issuer ${newTAO.did}`);
      await execCommand(`set payloadVcTI.credentialSubject.id ${newTI1.did}`);
      await execCommand(
        `set payloadVcTI.credentialSchema.id ${config.domain}/trusted-schemas-registry/v2/schemas/zjVFNvbEBPAr3a724DttioZpgZmNr75BBtRzZqk7pkDe`
      );
      await execCommand(
        `set payloadVcTI.termsOfUse.id ${newTAO.accreditation.url}`
      );
      newTI1.accreditation2.vc = await execCommand<string>(
        `compute createVcJwt payloadVcTI {} ES256K`
      );
      newTI1.accreditation2.id = removePrefix0x(
        sha256(Buffer.from(newTI1.accreditation2.vc))
      );
      newTI1.accreditation2.url = `${config.domain}/trusted-issuers-registry/v4/issuers/${newTI1.did}/attributes/${newTI1.accreditation2.id}`;

      let response = await execCommand(
        `tir updateIssuer ${newTI1.did} ${newTI1.accreditation2.vc} ti ${newTAO.did} ${newTAO.accreditation.id}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );
      response = await execCommand(`tir get /issuers/${newTI1.did}`);
      expect(response).toStrictEqual({
        did: newTI1.did,
        attributes: [
          {
            hash: newTI1.accreditation1.id,
            body: newTI1.accreditation1.vc,
            tao: newTAO.did,
            rootTao: newRootTAO.did,
            issuerType: "TI",
          },
          {
            hash: newTI1.accreditation2.id,
            body: newTI1.accreditation2.vc,
            tao: newTAO.did,
            rootTao: newRootTAO.did,
            issuerType: "TI",
          },
        ] as unknown[],
      });
    });

    it("should revoke a credential", async () => {
      expect.assertions(2);
      await loadUser(newTAO, "tokenTao");
      // TODO: how is the payload of a VC revoked?
      await execCommand(
        `payloadVcTI: load scripts/assets/VerifiableAccreditationToAttest.json`
      );
      await execCommand(`set payloadVcTI.issuer ${newTAO.did}`);
      await execCommand(`set payloadVcTI.credentialSubject.id ${newTI1.did}`);
      await execCommand(
        `set payloadVcTI.credentialSchema.id ${config.domain}/trusted-schemas-registry/v2/schemas/zjVFNvbEBPAr3a724DttioZpgZmNr75BBtRzZqk7pkDe`
      );
      await execCommand(
        `set payloadVcTI.termsOfUse.id ${newTAO.accreditation.url}`
      );
      newTI1.accreditation1.vc = await execCommand<string>(
        `compute createVcJwt payloadVcTI {} ES256K`
      );
      const revisionId = removePrefix0x(
        sha256(Buffer.from(newTI1.accreditation1.vc))
      );

      let response = await execCommand(
        `tir updateIssuer ${newTI1.did} ${newTI1.accreditation1.vc} revoked ${newTAO.did} ${newTAO.accreditation.id} ${newTI1.accreditation1.id}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      response = await execCommand(`tir get /issuers/${newTI1.did}`);
      expect(response).toStrictEqual({
        did: newTI1.did,
        attributes: [
          {
            hash: revisionId,
            body: newTI1.accreditation1.vc,
            tao: newTAO.did,
            rootTao: newRootTAO.did,
            issuerType: "Revoked",
          },
          {
            hash: newTI1.accreditation2.id,
            body: newTI1.accreditation2.vc,
            tao: newTAO.did,
            rootTao: newRootTAO.did,
            issuerType: "TI",
          },
        ] as unknown[],
      });
    });

    // invite + acceptance flow
    it("should invite and accept a new issuer", async () => {
      expect.assertions(3);

      // invitation from TAO (registration of metadata)
      await loadUser(newTAO, "tokenTao");
      await execCommand(
        `payloadVcTI: load scripts/assets/VerifiableAccreditationToAttest.json`
      );
      await execCommand(`set payloadVcTI.issuer ${newTAO.did}`);
      await execCommand(`set payloadVcTI.credentialSubject.id ${newTI2.did}`);
      await execCommand(
        `set payloadVcTI.credentialSchema.id ${config.domain}/trusted-schemas-registry/v2/schemas/zjVFNvbEBPAr3a724DttioZpgZmNr75BBtRzZqk7pkDe`
      );
      await execCommand(
        `set payloadVcTI.termsOfUse.id ${newTAO.accreditation.url}`
      );
      newTI2.accreditation.vc = await execCommand<string>(
        `compute createVcJwt payloadVcTI {} ES256K`
      );
      newTI2.accreditation.id = randomBytes(32).toString("hex");
      newTI2.accreditation.url = `${config.domain}/trusted-issuers-registry/v4/issuers/${newTI2.did}/attributes/${newTI2.accreditation.id}`;
      const newRevisionId = removePrefix0x(
        sha256(Buffer.from(newTI2.accreditation.vc))
      );

      let response = await execCommand(
        `tir setAttributeMetadata ${newTI2.did} ${newTI2.accreditation.id} ti ${newTAO.did} ${newTAO.accreditation.id}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      // acceptance from the new TI (registration of data)
      await loadUser(newTI2);
      await execCommand(
        `res: authorisation auth tir_invite_presentation ES256K ${newTI2.accreditation.vc}`
      );
      await execCommand("using token res.access_token");
      response = await execCommand(
        `tir setAttributeData ${newTI2.did} ${newTI2.accreditation.id} ${newTI2.accreditation.vc}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      // check the attributes of the new issuer
      response = await execCommand(`tir get /issuers/${newTI2.did}`);
      expect(response).toStrictEqual({
        did: newTI2.did,
        attributes: [
          {
            hash: newRevisionId, // should return the attribute ID?
            body: newTI2.accreditation.vc,
            tao: newTAO.did,
            rootTao: newRootTAO.did,
            issuerType: "TI",
          },
        ],
      });
    });

    it("should revoke a credential using the invite and acceptance flow", async () => {
      expect.assertions(3);

      // revocation from TAO (registration of metadata)
      await loadUser(newTAO, "tokenTao");
      // TODO: how is the payload of a VC revoked?
      await execCommand(
        `payloadVcTI: load scripts/assets/VerifiableAccreditationToAttest.json`
      );
      await execCommand(`set payloadVcTI.issuer ${newTAO.did}`);
      await execCommand(`set payloadVcTI.credentialSubject.id ${newTI2.did}`);
      await execCommand(
        `set payloadVcTI.credentialSchema.id ${config.domain}/trusted-schemas-registry/v2/schemas/zjVFNvbEBPAr3a724DttioZpgZmNr75BBtRzZqk7pkDe`
      );
      await execCommand(
        `set payloadVcTI.termsOfUse.id ${newTAO.accreditation.url}`
      );
      newTI2.accreditation.vc = await execCommand<string>(
        `compute createVcJwt payloadVcTI {} ES256K`
      );
      const revisionId = removePrefix0x(
        sha256(Buffer.from(newTI2.accreditation.vc))
      );
      newTI2.accreditation.url = `${config.domain}/trusted-issuers-registry/v4/issuers/${newTI2.did}/attributes/${newTI2.accreditation.id}`;

      let response = await execCommand(
        `tir setAttributeMetadata ${newTI2.did} ${newTI2.accreditation.id} revoked ${newTAO.did} ${newTAO.accreditation.id}`
      );

      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      // acceptance from the new TI (registration of revocation data)
      await loadUser(newTI2);
      await execCommand("res: authorisation auth tir_write_presentation");
      await execCommand("using token res.access_token");
      response = await execCommand(
        `tir setAttributeData ${newTI2.did} ${newTI2.accreditation.id} ${newTI2.accreditation.vc}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      // check the attributes of the new issuer
      response = await execCommand(`tir get /issuers/${newTI2.did}`);
      expect(response).toStrictEqual({
        did: newTI2.did,
        attributes: [
          {
            hash: revisionId,
            body: newTI2.accreditation.vc,
            tao: newTAO.did,
            rootTao: newRootTAO.did,
            issuerType: "Revoked",
          },
        ],
      });
    });

    it("should add/update proxy data", async () => {
      expect.assertions(3);
      await loadUser(newTI1);

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
        `proxyledger tir addIssuerProxy ${newTI1.did} ${proxyUtf8}`
      );
      expect(response).toStrictEqual(
        expect.objectContaining({
          transactionHash: expect.any(String) as string,
          status: "0x1",
        })
      );

      response = await execCommand(
        `tir get /issuers/${newTI1.did}/proxies/${proxyId}`
      );
      expect(response).toStrictEqual(proxyObject);

      // update issuer proxy
      proxyObject.prefix = "https://example.com";
      response = await execCommand(
        `proxyledger tir updateIssuerProxy ${
          newTI1.did
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
