import { calculateJwkThumbprint, JWK } from "jose";
import Joi from "joi";
import {
  Alg,
  BuildParamResponse,
  UnknownObject,
} from "../interfaces/shared/index.js";
import { Client } from "../utils/Client.js";
import { getPublicKeyHex, getPublicKeyJwk } from "../utils/utils.js";

export async function buildParamDid(
  method: string,
  client: Client,
  inputs: (string | UnknownObject)[]
): Promise<BuildParamResponse> {
  switch (method) {
    case "setRegistryAddresses": {
      return {
        info: { title: "initialization", data: method },
        param: {},
      };
    }
    case "insertDidDocument": {
      const [
        inputDid,
        inputBaseDocument,
        inputPublicKey,
        inputNotBefore,
        inputNotAfter,
        inputVMethodId,
      ] = inputs as [
        string,
        UnknownObject,
        UnknownObject | string,
        string,
        string,
        string
      ];
      Joi.assert(inputDid, Joi.string().optional());
      Joi.assert(inputNotBefore, Joi.string().optional());
      Joi.assert(inputNotAfter, Joi.string().optional());
      Joi.assert(inputVMethodId, Joi.string().optional());
      const did = inputDid || client.did;
      let baseDocument: string;
      let notBefore: number;
      let notAfter: number;
      let publicKey: string;
      let vMethodId: string;

      if (inputBaseDocument) {
        baseDocument = JSON.stringify(inputBaseDocument);
      } else {
        const didDocument = client.generateDidDocument();
        baseDocument = JSON.stringify({ "@context": didDocument["@context"] });
      }

      if (inputPublicKey) {
        if (typeof inputPublicKey !== "string") {
          throw new Error("the public key must be an hex string for secp256k1");
        }
        publicKey = inputPublicKey;
        const publicKeyJwk = getPublicKeyJwk(publicKey);
        vMethodId =
          inputVMethodId ||
          (await calculateJwkThumbprint(publicKeyJwk, "sha256"));
      } else {
        publicKey = client.ethWallet.publicKey;
        vMethodId = client.keys.ES256K.id;
      }
      const isSecp256k1 = true;

      if (inputNotBefore) {
        notBefore = Math.floor(new Date(inputNotBefore).getTime() / 1000);
      } else {
        notBefore = Math.floor(Date.now() / 1000);
      }

      if (inputNotAfter) {
        notAfter = Math.floor(new Date(inputNotAfter).getTime() / 1000);
      } else {
        notAfter = notBefore + 84600 * 365 * 5;
      }

      return {
        info: {
          title: "Did document",
          data: did,
        },
        param: {
          did,
          baseDocument,
          vMethodId,
          publicKey,
          isSecp256k1,
          notBefore,
          notAfter,
        },
      };
    }

    case "updateBaseDocument": {
      const [did, inputBaseDocument] = inputs as [string, UnknownObject];
      Joi.assert(did, Joi.string());

      let baseDocument: string;
      if (inputBaseDocument) {
        baseDocument = JSON.stringify(inputBaseDocument);
      } else {
        const didDocument = client.generateDidDocument();
        baseDocument = JSON.stringify({ "@context": didDocument["@context"] });
      }

      return {
        info: {
          title: "Update base document",
          data: {
            did,
            baseDocument,
          },
        },
        param: {
          did,
          baseDocument,
        },
      };
    }

    case "addController": {
      const [did, controller] = inputs as [string, string];
      Joi.assert(did, Joi.string());
      Joi.assert(controller, Joi.string());

      return {
        info: {
          title: "Add controller",
          data: { did, controller },
        },
        param: {
          did,
          controller,
        },
      };
    }

    case "revokeController": {
      const [did, controller] = inputs as [string, string];
      Joi.assert(did, Joi.string());
      Joi.assert(controller, Joi.string());

      return {
        info: {
          title: "Revoke controller",
          data: { did, controller },
        },
        param: {
          did,
          controller,
        },
      };
    }

    case "addVerificationMethod": {
      const [did, inputPublicKeyOrAlg, inputVMethodId] = inputs as [
        string,
        UnknownObject | string,
        string
      ];
      Joi.assert(did, Joi.string());
      Joi.assert(inputVMethodId, Joi.string().optional());

      let inputPublicKey = inputPublicKeyOrAlg;
      if (
        typeof inputPublicKeyOrAlg === "string" &&
        ["ES256K", "ES256", "RS256", "EdDSA"].includes(inputPublicKeyOrAlg)
      ) {
        const alg = inputPublicKeyOrAlg as Alg;
        inputPublicKey = client.keys[alg].publicKeyJwk;
      }

      let publicKey: string;
      let publicKeyJwk: JWK;
      let vMethodId: string;

      if (inputPublicKey) {
        if (typeof inputPublicKey === "string") {
          publicKey = inputPublicKey;
          publicKeyJwk = getPublicKeyJwk(publicKey);
        } else {
          publicKeyJwk = inputPublicKey;
          publicKey = getPublicKeyHex(publicKeyJwk);
        }
        vMethodId =
          inputVMethodId ||
          (await calculateJwkThumbprint(publicKeyJwk, "sha256"));
      } else {
        publicKey = client.ethWallet.publicKey;
        publicKeyJwk = getPublicKeyJwk(publicKey);
        vMethodId = client.keys.ES256K.id;
      }
      const isSecp256k1 = publicKeyJwk.crv === "secp256k1";

      return {
        info: {
          title: "Add verification method",
          data: {
            did,
            vMethodId,
            publicKey,
            isSecp256k1,
          },
        },
        param: {
          did,
          vMethodId,
          publicKey,
          isSecp256k1,
        },
      };
    }

    case "addVerificationRelationship": {
      const [did, name, vMethodIdOrAlg, inputNotBefore, inputNotAfter] =
        inputs as string[];
      Joi.assert(did, Joi.string());
      Joi.assert(
        name,
        Joi.string().valid(
          "authentication",
          "assertionMethod",
          "keyAgreement",
          "capabilityInvocation",
          "capabilityDelegation"
        )
      );
      Joi.assert(vMethodIdOrAlg, Joi.string());
      Joi.assert(inputNotBefore, Joi.string().optional());
      Joi.assert(inputNotAfter, Joi.string().optional());

      let notBefore: number;
      let notAfter: number;
      let vMethodId = vMethodIdOrAlg;
      if (["ES256K", "ES256", "RS256", "EdDSA"].includes(vMethodIdOrAlg)) {
        const alg = vMethodIdOrAlg as Alg;
        vMethodId = client.keys[alg].id;
      }

      if (inputNotBefore) {
        notBefore = Math.floor(new Date(inputNotBefore).getTime() / 1000);
      } else {
        notBefore = Math.floor(Date.now() / 1000);
      }

      if (inputNotAfter) {
        notAfter = Math.floor(new Date(inputNotAfter).getTime() / 1000);
      } else {
        notAfter = notBefore + 84600 * 365 * 5;
      }

      return {
        info: {
          title: "Add verification relationship",
          data: {
            did,
            name,
            vMethodId,
            notBefore,
            notAfter,
          },
        },
        param: {
          did,
          name,
          vMethodId,
          notBefore,
          notAfter,
        },
      };
    }

    case "revokeVerificationMethod": {
      const [did, vMethodIdOrAlg, inputNotAfter] = inputs as string[];
      Joi.assert(did, Joi.string());
      Joi.assert(vMethodIdOrAlg, Joi.string());
      Joi.assert(inputNotAfter, Joi.string());

      let notAfter: number;
      let vMethodId = vMethodIdOrAlg;
      if (["ES256K", "ES256", "RS256", "EdDSA"].includes(vMethodIdOrAlg)) {
        const alg = vMethodIdOrAlg as Alg;
        vMethodId = client.keys[alg].id;
      }

      if (inputNotAfter) {
        notAfter = Math.floor(new Date(inputNotAfter).getTime() / 1000);
      } else {
        notAfter = Math.floor(Date.now() / 1000);
      }

      return {
        info: {
          title: "Revoke verification method",
          data: {
            did,
            vMethodId,
            notAfter,
          },
        },
        param: {
          did,
          vMethodId,
          notAfter,
        },
      };
    }

    case "expireVerificationMethod": {
      const [did, vMethodIdOrAlg, inputNotAfter] = inputs as string[];
      Joi.assert(did, Joi.string());
      Joi.assert(vMethodIdOrAlg, Joi.string());
      Joi.assert(inputNotAfter, Joi.string());

      const notAfter = Math.floor(new Date(inputNotAfter).getTime() / 1000);

      let vMethodId = vMethodIdOrAlg;
      if (["ES256K", "ES256", "RS256", "EdDSA"].includes(vMethodIdOrAlg)) {
        const alg = vMethodIdOrAlg as Alg;
        vMethodId = client.keys[alg].id;
      }

      return {
        info: {
          title: "Expire verification method",
          data: {
            did,
            vMethodId,
            notAfter,
          },
        },
        param: {
          did,
          vMethodId,
          notAfter,
        },
      };
    }

    case "rollVerificationMethod": {
      const [
        did,
        inputPublicKeyOrAlg,
        inputNotBefore,
        inputNotAfter,
        oldVMethodId,
        inputDuration,
        inputVMethodId,
      ] = inputs as [
        string,
        UnknownObject | string,
        string,
        string,
        string,
        string,
        string
      ];
      Joi.assert(did, Joi.string());
      Joi.assert(inputNotBefore, Joi.string());
      Joi.assert(inputNotAfter, Joi.string());
      Joi.assert(oldVMethodId, Joi.string());
      Joi.assert(inputDuration, Joi.string());
      Joi.assert(inputVMethodId, Joi.string().optional());

      let inputPublicKey = inputPublicKeyOrAlg;
      if (
        typeof inputPublicKeyOrAlg === "string" &&
        ["ES256K", "ES256", "RS256", "EdDSA"].includes(inputPublicKeyOrAlg)
      ) {
        const alg = inputPublicKeyOrAlg as Alg;
        inputPublicKey = client.keys[alg].publicKeyJwk;
      }

      const notBefore = Math.floor(new Date(inputNotBefore).getTime() / 1000);
      const notAfter = Math.floor(new Date(inputNotAfter).getTime() / 1000);
      const duration = Number(inputDuration);

      let publicKey: string;
      let publicKeyJwk: JWK;
      let vMethodId: string;

      if (inputPublicKey) {
        if (typeof inputPublicKey === "string") {
          publicKey = inputPublicKey;
          publicKeyJwk = getPublicKeyJwk(publicKey);
        } else {
          publicKeyJwk = inputPublicKey;
          publicKey = getPublicKeyHex(publicKeyJwk);
        }
        vMethodId =
          inputVMethodId ||
          (await calculateJwkThumbprint(publicKeyJwk, "sha256"));
      } else {
        publicKey = client.ethWallet.publicKey;
        publicKeyJwk = getPublicKeyJwk(publicKey);
        vMethodId = client.keys.ES256K.id;
      }
      const isSecp256k1 = publicKeyJwk.crv === "secp256k1";

      return {
        info: {
          title: "Add verification method",
          data: {
            did,
            vMethodId,
            publicKey,
            isSecp256k1,
            notBefore,
            notAfter,
            oldVMethodId,
            duration,
          },
        },
        param: {
          did,
          vMethodId,
          publicKey,
          isSecp256k1,
          notBefore,
          notAfter,
          oldVMethodId,
          duration,
        },
      };
    }

    default:
      throw new Error(`Invalid method '${method}'`);
  }
}

export default buildParamDid;
