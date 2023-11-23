import { ethers } from "ethers";
import { auth, Client, types } from "cassandra-driver";
import * as dotenv from "dotenv";

// ABIs Test
import abiTimestampTest from "./abi/test/Timestamp.json" assert { type: "json" };
import abiTimestampNewTest from "./abi/test/TimestampV2.json" assert { type: "json" };
import abiDidTest from "./abi/test/DidRegistry.json" assert { type: "json" };
import abiDidOldTest from "./abi/test/DidRegistry-old.json" assert { type: "json" };
import abiDidNewTest from "./abi/test/DidRegistryV3.json" assert { type: "json" };
import abiTarTest from "./abi/test/Tar.json" assert { type: "json" };
import abiTarNewTest from "./abi/test/TarV3.json" assert { type: "json" };
import abiTirTest from "./abi/test/Tir.json" assert { type: "json" };
import abiTirNewTest from "./abi/test/TirV3.json" assert { type: "json" };
import abiTsrTest from "./abi/test/SchemaSCRegistry.json" assert { type: "json" };
import abiTsrNewTest from "./abi/test/SchemaSCRegistryV2.json" assert { type: "json" };
import abiTprTest from "./abi/test/Tpr.json" assert { type: "json" };
import abiTprNewTest from "./abi/test/TprV2.json" assert { type: "json" };

// ABIs Pilot
import abiTimestampPilot from "./abi/pilot/Timestamp.json" assert { type: "json" };
import abiTimestampNewPilot from "./abi/pilot/TimestampV2.json" assert { type: "json" };
import abiDidPilot from "./abi/pilot/DidRegistry.json" assert { type: "json" };
import abiDidOldPilot from "./abi/pilot/DidRegistry-old.json" assert { type: "json" };
import abiDidNewPilot from "./abi/pilot/DidRegistryV3.json" assert { type: "json" };
import abiTarPilot from "./abi/pilot/Tar.json" assert { type: "json" };
import abiTarNewPilot from "./abi/pilot/TarV3.json" assert { type: "json" };
import abiTirPilot from "./abi/pilot/Tir.json" assert { type: "json" };
import abiTirNewPilot from "./abi/pilot/TirV3.json" assert { type: "json" };
import abiTsrPilot from "./abi/pilot/SchemaSCRegistry.json" assert { type: "json" };
import abiTsrNewPilot from "./abi/pilot/SchemaSCRegistryV2.json" assert { type: "json" };
import abiTprPilot from "./abi/pilot/Tpr.json" assert { type: "json" };
import abiTprNewPilot from "./abi/pilot/TprV2.json" assert { type: "json" };

dotenv.config();

export type SupportedEnvs = "test" | "conformance" | "pilot" | "prod";

export interface ConfigApi {
  url: string;
  genericName?: string;
  id?: string;
  kid?: string;
  genericKid?: string;
  contract?: ethers.Contract;
  did?: string;
  urlCredentialSchema?: string;
  privateKey?: string;
}

export interface UserDetails {
  did: string;
  keyId?: string;
  privateKey: string;
  jwks?: {
    ES256: {
      privateKeyBase64: string;
      keyId: string;
    };
    RS256: {
      privateKeyBase64: string;
      keyId: string;
    };
    EdDSA: {
      privateKeyBase64: string;
      keyId: string;
    };
  };
}

export interface IssuerDetails extends UserDetails {
  accreditation: string;
}

interface ConfigVitest {
  resourceApp: {
    name: string;
    kid: string;
    id: string;
  };
  requesterApp: {
    name: string;
    id: string;
    kid: string;
    privateKey: string;
  };
  tprOperator: UserDetails;
  admin: IssuerDetails;
  issuer1: IssuerDetails;
  issuer2: IssuerDetails;
  user1: UserDetails;
  user2: UserDetails;
  user3: UserDetails;
  np: {
    [x: string]: {
      did: string;
      privateKeyBase64: string;
      vcJwt: string;
    };
  };
}

export interface Config {
  domain: string;
  contractAddresses: {
    timestamp: string;
    timestampNew: string;
    didOld?: string;
    did: string;
    didNew: string;
    tar: string;
    tarNew: string;
    tir: string;
    tirNew: string;
    tsr: string;
    tsrNew: string;
    tpr: string;
    tprNew: string;
  };
  api: {
    timestamp: ConfigApi;
    "timestamp-new": ConfigApi;
    storage: ConfigApi;
    ledger: ConfigApi;
    "ledger-new": ConfigApi;
    notifications: ConfigApi;
    authorisation: ConfigApi;
    "authorisation-new": ConfigApi;
    authorisationV2: ConfigApi;
    onboarding: ConfigApi;
    did: ConfigApi;
    "did-old": ConfigApi;
    "did-new": ConfigApi;
    datahub: ConfigApi;
    tar: ConfigApi;
    "tar-new": ConfigApi;
    tir: ConfigApi;
    "tir-new": ConfigApi;
    tsr: ConfigApi;
    "tsr-new": ConfigApi;
    tpr: ConfigApi;
    "tpr-new": ConfigApi;
    conformance: ConfigApi;
    conformanceV2: ConfigApi;
    "conformance-new": ConfigApi;
  };
  cassandra: {
    consistency: {
      read: types.consistencies;
      write: types.consistencies;
    };
    client: Client;
  };
  besuProvider: string;
  casUrl: string;
  onboardingService: string;
  timeoutMining: number;
  timeoutNotificationConformanceResponse: number;
  programs: {
    admin: {
      did: string;
      keyId: string;
      privateKey: string;
    };
  };
  vitest: ConfigVitest;
  vitestNew: ConfigVitest;
  env: SupportedEnvs;
  dockerServices: string[];
}

const configOpts = {
  test: {
    domain: "https://api-test.ebsi.eu",
    casUrl: "https://ecas.acceptance.ec.europa.eu/cas",
    besuProvider: process.env.TEST_BESU_PROVIDER,
    keyspace: "ebsi_test",
    contractAddresses: {
      timestamp: "0xCA40574d5aD8dBa0370A5E34eE830e4714a0Fa09",
      timestampNew: "0xCb9e9F0229f1492A22801B176196eCb158eb24B0",
      didOld: "0x15582f47140ff4bd74843583a1e3111032fb91c8",
      did: "0x823BBc0ceE3dE3B61AcfA0CEedb951AB9a013F05",
      didNew: "0x26E603f6FdCfC007c7bdC5be5f2c91D2a64a32E7",
      tar: "0x4d06B562588cb61616959806726c5D9f060b0F21",
      tarNew: "0x82Fd4865F702E2b319f3B2f1E4FDE5836883aC5D",
      tir: "0xFdfbCE7F3c12A902B79e0ceB0DB2662331bBA1aF",
      tirNew: "0xC2113689d64b794Dc311A38bFA1f7A1D5E4B6Cb9",
      tsr: "0x8E7E1387a72f9746B943187F6946E0e38b19FbFB",
      tsrNew: "0x3B3B6Faa80f88aD7Da4ff1451aE716Bf6f741700",
      tpr: "0x17a340418937A38b3Cb62FdA42241eB0722868A6",
      tprNew: "0x3d5edA0b5183e245bA9713B58834525EDfE46E90",
    },
    abi: {
      timestamp: abiTimestampTest,
      timestampNew: abiTimestampNewTest,
      did: abiDidTest,
      didOld: abiDidOldTest,
      didNew: abiDidNewTest,
      tar: abiTarTest,
      tarNew: abiTarNewTest,
      tir: abiTirTest,
      tirNew: abiTirNewTest,
      tsr: abiTsrTest,
      tsrNew: abiTsrNewTest,
      tpr: abiTprTest,
      tprNew: abiTprNewTest,
    },
    // variables for testing
    authorisationApiId:
      "0xf0c34a721e1bb7606de33a6e44ab30698e8076d7bb5c0b11d108aa52a5de0337",
    authorisationApiDid: "did:ebsi:zcPNLbvojYtj7R3B6pJXaFy",
    onboardingApiDid: "did:ebsi:zwC56DZdiJh8kSxbgg4fMCu",
    onboardingApiKid: "did:ebsi:zwC56DZdiJh8kSxbgg4fMCu#keys-1",
    onboardingApiPrivateKey: process.env.TEST_ONBOARDING_API_PRIVATE_KEY,
    conformanceApiV2Did: "did:ebsi:zicftVRNkkwfRourZd3nE5f",
    conformanceApiV3Did: "did:ebsi:zy8jAhPDbhwKN74YFWAUzD5",
    conformanceApiV4Did: "did:ebsi:ztTYEydcPQ2SrKoghHqxBfK",
    programs: {
      admin: {
        did: process.env.TEST_PROGRAMS_ADMIN_DID,
        keyId: process.env.TEST_PROGRAMS_ADMIN_KEY_ID,
        privateKey: process.env.TEST_PROGRAMS_ADMIN_PRIVATE_KEY,
      },
    },
    vitest: {
      resourceApp: {
        name: process.env.TEST_RESOURCE_APP_NAME,
        id: process.env.TEST_RESOURCE_APP_ID,
        kid: `https://api-test.ebsi.eu/trusted-apps-registry/v3/apps/${process.env.TEST_RESOURCE_APP_NAME}`,
      },
      requesterApp: {
        name: process.env.TEST_REQUESTER_APP_NAME,
        id: process.env.TEST_REQUESTER_APP_ID,
        kid: `https://api-test.ebsi.eu/trusted-apps-registry/v3/apps/${process.env.TEST_REQUESTER_APP_NAME}`,
        privateKey: process.env.TEST_REQUESTER_APP_PRIVATE_KEY,
      },
      tprOperator: {
        did: process.env.TEST_TPR_OPERATOR_DID,
        keyId: process.env.TEST_TPR_OPERATOR_KEY_ID,
        privateKey: process.env.TEST_TPR_OPERATOR_PRIVATE_KEY,
      },
      admin: {
        did: process.env.TEST_ADMIN_DID,
        keyId: process.env.TEST_ADMIN_KEY_ID,
        privateKey: process.env.TEST_ADMIN_PRIVATE_KEY,
        accreditation: process.env.TEST_ADMIN_ACCREDITATION,
      },
      issuer1: {
        did: process.env.TEST_ISSUER_1_DID,
        keyId: process.env.TEST_ISSUER_1_ES256K_KEY_ID,
        accreditation: process.env.TEST_ISSUER_1_ACCREDITATION,
        privateKey: process.env.TEST_ISSUER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.TEST_ISSUER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.TEST_ISSUER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.TEST_ISSUER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.TEST_ISSUER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.TEST_ISSUER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.TEST_ISSUER_1_EDDSA_KEY_ID,
          },
        },
      },
      issuer2: {
        did: process.env.TEST_ISSUER_2_DID,
        keyId: process.env.TEST_ISSUER_2_KEY_ID,
        accreditation: process.env.TEST_ISSUER_2_ACCREDITATION,
        privateKey: process.env.TEST_ISSUER_2_PRIVATE_KEY,
      },
      user1: {
        did: process.env.TEST_USER_1_DID,
        keyId: process.env.TEST_USER_1_ES256K_KEY_ID,
        privateKey: process.env.TEST_USER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.TEST_USER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.TEST_USER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.TEST_USER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.TEST_USER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.TEST_USER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.TEST_USER_1_EDDSA_KEY_ID,
          },
        },
      },
      user2: {
        did: process.env.TEST_USER_2_DID,
        keyId: process.env.TEST_USER_2_KEY_ID,
        privateKey: process.env.TEST_USER_2_PRIVATE_KEY,
      },
      user3: {
        did: process.env.TEST_USER_3_DID,
        keyId: process.env.TEST_USER_3_KEY_ID,
        privateKey: process.env.TEST_USER_3_PRIVATE_KEY,
      },
      np: {
        ES256K: {
          did: process.env.TEST_NP_ES256K_DID,
          privateKeyBase64: process.env.TEST_NP_PRIVATE_KEY_JWK_ES256K_BASE64,
          vcJwt: process.env.TEST_NP_ES256K_VC,
        },
        ES256: {
          did: process.env.TEST_NP_ES256_DID,
          privateKeyBase64: process.env.TEST_NP_PRIVATE_KEY_JWK_ES256_BASE64,
          vcJwt: process.env.TEST_NP_ES256_VC,
        },
        RS256: {
          did: process.env.TEST_NP_RS256_DID,
          privateKeyBase64: process.env.TEST_NP_PRIVATE_KEY_JWK_RS256_BASE64,
          vcJwt: process.env.TEST_NP_RS256_VC,
        },
        EdDSA: {
          did: process.env.TEST_NP_EDDSA_DID,
          privateKeyBase64: process.env.TEST_NP_PRIVATE_KEY_JWK_EDDSA_BASE64,
          vcJwt: process.env.TEST_NP_EDDSA_VC,
        },
      },
    },
    vitestNew: {
      resourceApp: {
        name: process.env.TEST_NEW_RESOURCE_APP_NAME,
        id: process.env.TEST_NEW_RESOURCE_APP_ID,
        kid: `https://api-test.ebsi.eu/trusted-apps-registry/v4/apps/${process.env.TEST_NEW_RESOURCE_APP_NAME}`,
      },
      requesterApp: {
        name: process.env.TEST_NEW_REQUESTER_APP_NAME,
        id: process.env.TEST_NEW_REQUESTER_APP_ID,
        kid: `https://api-test.ebsi.eu/trusted-apps-registry/v4/apps/${process.env.TEST_NEW_REQUESTER_APP_NAME}`,
        privateKey: process.env.TEST_NEW_REQUESTER_APP_PRIVATE_KEY,
      },
      tprOperator: {
        did: process.env.TEST_NEW_TPR_OPERATOR_DID,
        keyId: process.env.TEST_NEW_TPR_OPERATOR_KEY_ID,
        privateKey: process.env.TEST_NEW_TPR_OPERATOR_PRIVATE_KEY,
      },
      admin: {
        did: process.env.TEST_NEW_ADMIN_DID,
        keyId: process.env.TEST_NEW_ADMIN_KEY_ID,
        privateKey: process.env.TEST_NEW_ADMIN_PRIVATE_KEY,
        accreditation: process.env.TEST_NEW_ADMIN_ACCREDITATION,
      },
      issuer1: {
        did: process.env.TEST_NEW_ISSUER_1_DID,
        keyId: process.env.TEST_NEW_ISSUER_1_ES256K_KEY_ID,
        accreditation: process.env.TEST_NEW_ISSUER_1_ACCREDITATION,
        privateKey: process.env.TEST_NEW_ISSUER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.TEST_NEW_ISSUER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.TEST_NEW_ISSUER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.TEST_NEW_ISSUER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.TEST_NEW_ISSUER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.TEST_NEW_ISSUER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.TEST_NEW_ISSUER_1_EDDSA_KEY_ID,
          },
        },
      },
      issuer2: {
        did: process.env.TEST_NEW_ISSUER_2_DID,
        keyId: process.env.TEST_NEW_ISSUER_2_KEY_ID,
        accreditation: process.env.TEST_NEW_ISSUER_2_ACCREDITATION,
        privateKey: process.env.TEST_NEW_ISSUER_2_PRIVATE_KEY,
      },
      user1: {
        did: process.env.TEST_NEW_USER_1_DID,
        keyId: process.env.TEST_NEW_USER_1_ES256K_KEY_ID,
        privateKey: process.env.TEST_NEW_USER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.TEST_NEW_USER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.TEST_NEW_USER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.TEST_NEW_USER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.TEST_NEW_USER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.TEST_NEW_USER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.TEST_NEW_USER_1_EDDSA_KEY_ID,
          },
        },
      },
      user2: {
        did: process.env.TEST_NEW_USER_2_DID,
        keyId: process.env.TEST_NEW_USER_2_KEY_ID,
        privateKey: process.env.TEST_NEW_USER_2_PRIVATE_KEY,
      },
      user3: {
        did: process.env.TEST_NEW_USER_3_DID,
        keyId: process.env.TEST_NEW_USER_3_KEY_ID,
        privateKey: process.env.TEST_NEW_USER_3_PRIVATE_KEY,
      },
      np: {},
    },
  },
  pilot: {
    domain: "https://api-pilot.ebsi.eu",
    casUrl: "https://ecas.ec.europa.eu/cas",
    besuProvider: process.env.PILOT_BESU_PROVIDER,
    keyspace: "ebsi_pilot",
    contractAddresses: {
      timestamp: "0xaD00Eb7A224cBB0f3fCeC68595a4F4FF87e7eB2F",
      timestampNew: "0x8b7ddD28FdE20080A337Bff5badCa043163Bc3a3",
      didOld: "0xD55bDf1407E57D55C92BdB67088ECdA554b76B45",
      did: "0x755DEd5d5e81282F0BE85EDaE8e6852814bAC3fa",
      didNew: "0x76C8190D7422e5fa2A0190Bc2313bab0b2afEC78",
      tar: "0x3Ba8dE431d3741A6077A20656aCC01027FF920e3",
      tarNew: "0x35fE6e9be02Bc93381117e6c424B5688894B0639",
      tir: "0xB1D9B0EC0B52aD095bab2A5320a808aCb7c9F186",
      tirNew: "0x5C87455c82617579A10AD39C2DB3e60E846E7266",
      tsr: "0x30cC78D20E21C8422F3B62052FD4C15D4b7894A4",
      tsrNew: "0xF3aFc480b171CB8c2D89c3753FF46104d7011B07",
      tpr: "0x3591e30eaea83343ed69A077D059821c5099154A",
      tprNew: "0x81872fccf3AEDD94C00E643bC2967Bd7aC91CFEB",
    },
    abi: {
      timestamp: abiTimestampPilot,
      timestampNew: abiTimestampNewPilot,
      did: abiDidPilot,
      didOld: abiDidOldPilot,
      didNew: abiDidNewPilot,
      tar: abiTarPilot,
      tarNew: abiTarNewPilot,
      tir: abiTirPilot,
      tirNew: abiTirNewPilot,
      tsr: abiTsrPilot,
      tsrNew: abiTsrNewPilot,
      tpr: abiTprPilot,
      tprNew: abiTprNewPilot,
    },
    // variables for testing
    authorisationApiId:
      "0x559c4f32dc35566e4b92b697499c38f3847a6c53f8344821c24354ead1f2ab1e",
    authorisationApiDid: "did:ebsi:znHeZWvhAK2FK2Dk1jXNe7m",
    onboardingApiDid: "did:ebsi:zr2rWDHHrUCdZAW7wsSb5nQ",
    onboardingApiKid: "did:ebsi:zr2rWDHHrUCdZAW7wsSb5nQ#keys-1",
    onboardingApiPrivateKey: process.env.PILOT_ONBOARDING_API_PRIVATE_KEY,
    conformanceApiV2Did: "",
    conformanceApiV3Did: "",
    conformanceApiV4Did: "",
    programs: {
      admin: {
        did: process.env.PILOT_PROGRAMS_ADMIN_DID,
        keyId: process.env.PILOT_PROGRAMS_ADMIN_KEY_ID,
        privateKey: process.env.PILOT_PROGRAMS_ADMIN_PRIVATE_KEY,
      },
    },
    vitest: {
      resourceApp: {
        name: process.env.PILOT_RESOURCE_APP_NAME,
        id: process.env.PILOT_RESOURCE_APP_ID,
        kid: `https://api-pilot.ebsi.eu/trusted-apps-registry/v3/apps/${process.env.PILOT_RESOURCE_APP_NAME}`,
      },
      requesterApp: {
        name: process.env.PILOT_REQUESTER_APP_NAME,
        id: process.env.PILOT_REQUESTER_APP_ID,
        kid: `https://api-pilot.ebsi.eu/trusted-apps-registry/v3/apps/${process.env.PILOT_REQUESTER_APP_NAME}`,
        privateKey: process.env.PILOT_REQUESTER_APP_PRIVATE_KEY,
      },
      tprOperator: {
        did: "",
        keyId: "",
        privateKey: "",
      },
      admin: {
        did: process.env.PILOT_ADMIN_DID,
        keyId: "",
        privateKey: "",
        accreditation: "",
      },
      issuer1: {
        did: process.env.PILOT_ISSUER_1_DID,
        keyId: "",
        accreditation: "",
        privateKey: "",
      },
      issuer2: {
        did: "",
        keyId: "",
        accreditation: "",
        privateKey: "",
      },
      user1: {
        did: process.env.PILOT_USER_1_DID,
        keyId: process.env.PILOT_USER_1_ES256K_KEY_ID,
        privateKey: process.env.PILOT_USER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.PILOT_USER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.PILOT_USER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.PILOT_USER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.PILOT_USER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.PILOT_USER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.PILOT_USER_1_EDDSA_KEY_ID,
          },
        },
      },
      user2: {
        did: process.env.PILOT_USER_2_DID,
        keyId: process.env.PILOT_USER_2_KEY_ID,
        privateKey: process.env.PILOT_USER_2_PRIVATE_KEY,
      },
      user3: {
        did: process.env.PILOT_USER_3_DID,
        keyId: process.env.PILOT_USER_3_KEY_ID,
        privateKey: process.env.PILOT_USER_3_PRIVATE_KEY,
      },
      np: {
        ES256K: {
          did: process.env.PILOT_NP_ES256K_DID,
          privateKeyBase64: process.env.PILOT_NP_PRIVATE_KEY_JWK_ES256K_BASE64,
          vcJwt: process.env.PILOT_NP_ES256K_VC,
        },
        ES256: {
          did: process.env.PILOT_NP_ES256_DID,
          privateKeyBase64: process.env.PILOT_NP_PRIVATE_KEY_JWK_ES256_BASE64,
          vcJwt: process.env.PILOT_NP_ES256_VC,
        },
        RS256: {
          did: process.env.PILOT_NP_RS256_DID,
          privateKeyBase64: process.env.PILOT_NP_PRIVATE_KEY_JWK_RS256_BASE64,
          vcJwt: process.env.PILOT_NP_RS256_VC,
        },
        EdDSA: {
          did: process.env.PILOT_NP_EDDSA_DID,
          privateKeyBase64: process.env.PILOT_NP_PRIVATE_KEY_JWK_EDDSA_BASE64,
          vcJwt: process.env.PILOT_NP_EDDSA_VC,
        },
      },
    },
    vitestNew: {
      resourceApp: {
        name: process.env.PILOT_NEW_RESOURCE_APP_NAME,
        id: process.env.PILOT_NEW_RESOURCE_APP_ID,
        kid: `https://api-pilot.ebsi.eu/trusted-apps-registry/v4/apps/${process.env.PILOT_NEW_RESOURCE_APP_NAME}`,
      },
      requesterApp: {
        name: process.env.PILOT_NEW_REQUESTER_APP_NAME,
        id: process.env.PILOT_NEW_REQUESTER_APP_ID,
        kid: `https://api-pilot.ebsi.eu/trusted-apps-registry/v4/apps/${process.env.PILOT_NEW_REQUESTER_APP_NAME}`,
        privateKey: process.env.PILOT_NEW_REQUESTER_APP_PRIVATE_KEY,
      },
      tprOperator: {
        did: "",
        keyId: "",
        privateKey: "",
      },
      admin: {
        did: process.env.PILOT_NEW_ADMIN_DID,
        keyId: "",
        privateKey: "",
        accreditation: "",
      },
      issuer1: {
        did: process.env.PILOT_NEW_ISSUER_1_DID,
        keyId: "",
        accreditation: "",
        privateKey: "",
      },
      issuer2: {
        did: "",
        keyId: "",
        accreditation: "",
        privateKey: "",
      },
      user1: {
        did: process.env.PILOT_NEW_USER_1_DID,
        keyId: process.env.PILOT_NEW_USER_1_ES256K_KEY_ID,
        privateKey: process.env.PILOT_NEW_USER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.PILOT_NEW_USER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.PILOT_NEW_USER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.PILOT_NEW_USER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.PILOT_NEW_USER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.PILOT_NEW_USER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.PILOT_NEW_USER_1_EDDSA_KEY_ID,
          },
        },
      },
      user2: {
        did: process.env.PILOT_NEW_USER_2_DID,
        keyId: process.env.PILOT_NEW_USER_2_KEY_ID,
        privateKey: process.env.PILOT_NEW_USER_2_PRIVATE_KEY,
      },
      user3: {
        did: process.env.PILOT_NEW_USER_3_DID,
        keyId: process.env.PILOT_NEW_USER_3_KEY_ID,
        privateKey: process.env.PILOT_NEW_USER_3_PRIVATE_KEY,
      },
      np: {},
    },
  },
  conformance: {
    domain: "https://api-conformance.ebsi.eu",
    casUrl: "https://ecas.ec.europa.eu/cas",
    besuProvider: process.env.CONFORMANCE_BESU_PROVIDER,
    keyspace: "ebsi_conformance",
    contractAddresses: {
      timestamp: "0xaD00Eb7A224cBB0f3fCeC68595a4F4FF87e7eB2F",
      timestampNew: "0xF75917CD450602d78425901B6765111193cFD06f",
      didOld: "0x36cf4f85c6d7d40B243314E4FA665bE626E59Ba5",
      didNew: "0xf15e3682BCe7ADDefb2F1E1EAE3163448DB539f6",
      did: "0x4Fa9Dbee2E7CF24737348D5249Db7F94fA45f099",
      tar: "0x3Ba8dE431d3741A6077A20656aCC01027FF920e3",
      tarNew: "0xDEdDF7bDa978828b3ed425791978EF9cf99CabD3",
      tir: "0xB1D9B0EC0B52aD095bab2A5320a808aCb7c9F186",
      tirNew: "0x24A84106AF7DfB216d0a69cEf06ae5413CA46C15",
      tsr: "0x30cC78D20E21C8422F3B62052FD4C15D4b7894A4",
      tsrNew: "0x76d0Ce94a6f2F07179ff48fc355FDa7Ff8C71A2C",
      tpr: "0x3591e30eaea83343ed69A077D059821c5099154A",
      tprNew: "0x38CcCfA3208dd65c2516C8004b142C1447Add3C2",
    },
    abi: {
      timestamp: abiTimestampPilot,
      timestampNew: abiTimestampNewPilot,
      did: abiDidPilot,
      didOld: abiDidOldPilot,
      didNew: abiDidNewPilot,
      tar: abiTarPilot,
      tarNew: abiTarNewPilot,
      tir: abiTirPilot,
      tirNew: abiTirNewPilot,
      tsr: abiTsrPilot,
      tsrNew: abiTsrNewPilot,
      tpr: abiTprPilot,
      tprNew: abiTprNewPilot,
    },
    // variables for testing
    authorisationApiId:
      "0x559c4f32dc35566e4b92b697499c38f3847a6c53f8344821c24354ead1f2ab1e",
    authorisationApiDid: "did:ebsi:zkgWUcRsW8DiuEzXBcDtWrF",
    onboardingApiDid: "did:ebsi:zeG8Qa84ZCZFoECmGjxiZcM",
    onboardingApiKid: "did:ebsi:zeG8Qa84ZCZFoECmGjxiZcM#keys-1",
    onboardingApiPrivateKey: process.env.CONFORMANCE_ONBOARDING_API_PRIVATE_KEY,
    conformanceApiV2Did: "did:ebsi:zcfcwGjLBojczw9yhmUFE3Z",
    conformanceApiV3Did: "did:ebsi:zhJARjPN69cEtgPxHen1Mid",
    conformanceApiV4Did: "did:ebsi:zjHZjJ4Sy7r92BxXzFGs7qD",
    programs: {
      admin: {
        did: process.env.CONFORMANCE_PROGRAMS_ADMIN_DID,
        keyId: process.env.CONFORMANCE_PROGRAMS_ADMIN_KEY_ID,
        privateKey: process.env.CONFORMANCE_PROGRAMS_ADMIN_PRIVATE_KEY,
      },
    },
    vitest: {
      resourceApp: {
        name: process.env.CONFORMANCE_RESOURCE_APP_NAME,
        id: process.env.CONFORMANCE_RESOURCE_APP_ID,
        kid: `https://api-conformance.ebsi.eu/trusted-apps-registry/v3/apps/${process.env.CONFORMANCE_RESOURCE_APP_NAME}`,
      },
      requesterApp: {
        name: process.env.CONFORMANCE_REQUESTER_APP_NAME,
        id: process.env.CONFORMANCE_REQUESTER_APP_ID,
        kid: `https://api-conformance.ebsi.eu/trusted-apps-registry/v3/apps/${process.env.CONFORMANCE_REQUESTER_APP_NAME}`,
        privateKey: process.env.CONFORMANCE_REQUESTER_APP_PRIVATE_KEY,
      },
      tprOperator: {
        did: process.env.CONFORMANCE_TPR_OPERATOR_DID,
        keyId: process.env.CONFORMANCE_TPR_OPERATOR_KEY_ID,
        privateKey: process.env.CONFORMANCE_TPR_OPERATOR_PRIVATE_KEY,
      },
      admin: {
        did: process.env.CONFORMANCE_ADMIN_DID,
        keyId: process.env.CONFORMANCE_ADMIN_KEY_ID,
        privateKey: process.env.CONFORMANCE_ADMIN_PRIVATE_KEY,
        accreditation: process.env.CONFORMANCE_ADMIN_ACCREDITATION,
      },
      issuer1: {
        did: process.env.CONFORMANCE_ISSUER_1_DID,
        keyId: process.env.CONFORMANCE_ISSUER_1_ES256K_KEY_ID,
        accreditation: process.env.CONFORMANCE_ISSUER_1_ACCREDITATION,
        privateKey: process.env.CONFORMANCE_ISSUER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.CONFORMANCE_ISSUER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.CONFORMANCE_ISSUER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.CONFORMANCE_ISSUER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.CONFORMANCE_ISSUER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.CONFORMANCE_ISSUER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.CONFORMANCE_ISSUER_1_EDDSA_KEY_ID,
          },
        },
      },
      issuer2: {
        did: process.env.CONFORMANCE_ISSUER_2_DID,
        keyId: process.env.CONFORMANCE_ISSUER_2_KEY_ID,
        accreditation: process.env.CONFORMANCE_ISSUER_2_ACCREDITATION,
        privateKey: process.env.CONFORMANCE_ISSUER_2_PRIVATE_KEY,
      },
      user1: {
        did: process.env.CONFORMANCE_USER_1_DID,
        keyId: process.env.CONFORMANCE_USER_1_ES256K_KEY_ID,
        privateKey: process.env.CONFORMANCE_USER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.CONFORMANCE_USER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.CONFORMANCE_USER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.CONFORMANCE_USER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.CONFORMANCE_USER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.CONFORMANCE_USER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.CONFORMANCE_USER_1_EDDSA_KEY_ID,
          },
        },
      },
      user2: {
        did: process.env.CONFORMANCE_USER_2_DID,
        keyId: process.env.CONFORMANCE_USER_2_KEY_ID,
        privateKey: process.env.CONFORMANCE_USER_2_PRIVATE_KEY,
      },
      user3: {
        did: process.env.CONFORMANCE_USER_3_DID,
        keyId: process.env.CONFORMANCE_USER_3_KEY_ID,
        privateKey: process.env.CONFORMANCE_USER_3_PRIVATE_KEY,
      },
      np: {
        ES256K: {
          did: process.env.CONFORMANCE_NP_ES256K_DID,
          privateKeyBase64:
            process.env.CONFORMANCE_NP_PRIVATE_KEY_JWK_ES256K_BASE64,
          vcJwt: process.env.CONFORMANCE_NP_ES256K_VC,
        },
        ES256: {
          did: process.env.CONFORMANCE_NP_ES256_DID,
          privateKeyBase64:
            process.env.CONFORMANCE_NP_PRIVATE_KEY_JWK_ES256_BASE64,
          vcJwt: process.env.CONFORMANCE_NP_ES256_VC,
        },
        RS256: {
          did: process.env.CONFORMANCE_NP_RS256_DID,
          privateKeyBase64:
            process.env.CONFORMANCE_NP_PRIVATE_KEY_JWK_RS256_BASE64,
          vcJwt: process.env.CONFORMANCE_NP_RS256_VC,
        },
        EdDSA: {
          did: process.env.CONFORMANCE_NP_EDDSA_DID,
          privateKeyBase64:
            process.env.CONFORMANCE_NP_PRIVATE_KEY_JWK_EDDSA_BASE64,
          vcJwt: process.env.CONFORMANCE_NP_EDDSA_VC,
        },
      },
    },
    vitestNew: {
      resourceApp: {
        name: process.env.CONFORMANCE_NEW_RESOURCE_APP_NAME,
        id: process.env.CONFORMANCE_NEW_RESOURCE_APP_ID,
        kid: `https://api-conformance.ebsi.eu/trusted-apps-registry/v4/apps/${process.env.CONFORMANCE_NEW_RESOURCE_APP_NAME}`,
      },
      requesterApp: {
        name: process.env.CONFORMANCE_NEW_REQUESTER_APP_NAME,
        id: process.env.CONFORMANCE_NEW_REQUESTER_APP_ID,
        kid: `https://api-conformance.ebsi.eu/trusted-apps-registry/v4/apps/${process.env.CONFORMANCE_NEW_REQUESTER_APP_NAME}`,
        privateKey: process.env.CONFORMANCE_NEW_REQUESTER_APP_PRIVATE_KEY,
      },
      tprOperator: {
        did: process.env.CONFORMANCE_NEW_TPR_OPERATOR_DID,
        keyId: process.env.CONFORMANCE_NEW_TPR_OPERATOR_KEY_ID,
        privateKey: process.env.CONFORMANCE_NEW_TPR_OPERATOR_PRIVATE_KEY,
      },
      admin: {
        did: process.env.CONFORMANCE_NEW_ADMIN_DID,
        keyId: process.env.CONFORMANCE_NEW_ADMIN_KEY_ID,
        privateKey: process.env.CONFORMANCE_NEW_ADMIN_PRIVATE_KEY,
        accreditation: process.env.CONFORMANCE_NEW_ADMIN_ACCREDITATION,
      },
      issuer1: {
        did: process.env.CONFORMANCE_NEW_ISSUER_1_DID,
        keyId: process.env.CONFORMANCE_NEW_ISSUER_1_ES256K_KEY_ID,
        accreditation: process.env.CONFORMANCE_NEW_ISSUER_1_ACCREDITATION,
        privateKey: process.env.CONFORMANCE_NEW_ISSUER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.CONFORMANCE_NEW_ISSUER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.CONFORMANCE_NEW_ISSUER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.CONFORMANCE_NEW_ISSUER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.CONFORMANCE_NEW_ISSUER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.CONFORMANCE_NEW_ISSUER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.CONFORMANCE_NEW_ISSUER_1_EDDSA_KEY_ID,
          },
        },
      },
      issuer2: {
        did: process.env.CONFORMANCE_NEW_ISSUER_2_DID,
        keyId: process.env.CONFORMANCE_NEW_ISSUER_2_KEY_ID,
        accreditation: process.env.CONFORMANCE_NEW_ISSUER_2_ACCREDITATION,
        privateKey: process.env.CONFORMANCE_NEW_ISSUER_2_PRIVATE_KEY,
      },
      user1: {
        did: process.env.CONFORMANCE_NEW_USER_1_DID,
        keyId: process.env.CONFORMANCE_NEW_USER_1_ES256K_KEY_ID,
        privateKey: process.env.CONFORMANCE_NEW_USER_1_PRIVATE_KEY,
        jwks: {
          ES256: {
            privateKeyBase64:
              process.env.CONFORMANCE_NEW_USER_1_PRIVATE_KEY_JWK_ES256_BASE64,
            keyId: process.env.CONFORMANCE_NEW_USER_1_ES256_KEY_ID,
          },
          RS256: {
            privateKeyBase64:
              process.env.CONFORMANCE_NEW_USER_1_PRIVATE_KEY_JWK_RS256_BASE64,
            keyId: process.env.CONFORMANCE_NEW_USER_1_RS256_KEY_ID,
          },
          EdDSA: {
            privateKeyBase64:
              process.env.CONFORMANCE_NEW_USER_1_PRIVATE_KEY_JWK_EDDSA_BASE64,
            keyId: process.env.CONFORMANCE_NEW_USER_1_EDDSA_KEY_ID,
          },
        },
      },
      user2: {
        did: process.env.CONFORMANCE_NEW_USER_2_DID,
        keyId: process.env.CONFORMANCE_NEW_USER_2_KEY_ID,
        privateKey: process.env.CONFORMANCE_NEW_USER_2_PRIVATE_KEY,
      },
      user3: {
        did: process.env.CONFORMANCE_NEW_USER_3_DID,
        keyId: process.env.CONFORMANCE_NEW_USER_3_KEY_ID,
        privateKey: process.env.CONFORMANCE_NEW_USER_3_PRIVATE_KEY,
      },
      np: {},
    },
  },
};

function setDomain(value: string, domain: string) {
  const v = value.substring(value.lastIndexOf("/") + 1);
  return `${domain}/${v}`;
}

export const loadConfig = (
  env = (process.env.EBSI_ENV || "test") as SupportedEnvs
): Config => {
  const sharedConfig = configOpts[env as "test" | "pilot" | "conformance"];
  const timeoutMining =
    Number(process.env.TIMEOUT_MINING) || Number.MAX_SAFE_INTEGER;
  const timeoutNotificationConformanceResponse =
    Number(process.env.TIMEOUT_NOTIFICATION_CONFORMANCE_RESPONSE) ||
    Number.MAX_SAFE_INTEGER;
  const dockerServices = process.env.DOCKER_SERVICES
    ? process.env.DOCKER_SERVICES.split(",")
    : [
        "authorisation-api",
        "did-registry-api",
        "notifications-api",
        "proxy-data-hub-api",
        "timestamp-api",
        "trusted-issuers-registry-api",
        "trusted-policies-registry-api",
        "trusted-schemas-registry-api",
        "users-onboarding-api",
      ];
  const {
    domain: domainEnv,
    contractAddresses,
    abi,
    keyspace,
    besuProvider,
    casUrl,
    authorisationApiId,
    authorisationApiDid,
    onboardingApiDid,
    onboardingApiKid,
    onboardingApiPrivateKey, // only for testing
    conformanceApiV2Did,
    conformanceApiV3Did,
    conformanceApiV4Did,
    programs,
    vitest,
    vitestNew,
  } = sharedConfig;
  const domain = process.env.DOMAIN ?? domainEnv;
  const api = {
    // Integration API
    "timestamp-new": {
      url: `${domain}/timestamp/v4`,
      genericName: "timestamp-api",
      contract: new ethers.Contract(
        contractAddresses.timestampNew,
        abi.timestampNew
      ),
    },
    timestamp: {
      url: `${domain}/timestamp/v3`,
      genericName: "timestamp-api",
      contract: new ethers.Contract(contractAddresses.timestamp, abi.timestamp),
    },
    storage: {
      url: `${domain}/storage/v3`,
      genericName: "storage-api",
    },
    "ledger-new": {
      url: `${domain}/ledger/v4`,
      genericName: "ledger-api",
    },
    ledger: {
      url: `${domain}/ledger/v3`,
      genericName: "ledger-api",
    },
    notifications: {
      url: `${domain}/notifications/v2`,
      genericName: "notifications-api",
    },
    "authorisation-new": {
      url: `${domain}/authorisation/v4`,
      genericName: "authorisation-api",
      id: authorisationApiId,
      genericKid: `${domain}/trusted-apps-registry/v5/apps/authorisation-api`,
      urlCredentialSchema: `${domain}/trusted-schemas-registry/v3/schemas/0x312e332e362e312e342e312e313338312e332e31322e332e322e332e3738`,
    },
    authorisation: {
      url: `${domain}/authorisation/v3`,
      genericName: "authorisation-api",
      id: authorisationApiId,
      genericKid: `${domain}/trusted-apps-registry/v4/apps/authorisation-api`,
      did: authorisationApiDid,
      urlCredentialSchema: `${domain}/trusted-schemas-registry/v2/schemas/0x312e332e362e312e342e312e313338312e332e31322e332e322e332e3738`,
    },
    authorisationV2: {
      url: `${domain}/authorisation/v2`,
      genericName: "authorisation-api",
      id: authorisationApiId,
      genericKid: `${domain}/trusted-apps-registry/v3/apps/authorisation-api`,
      did: authorisationApiDid,
      urlCredentialSchema: `${domain}/trusted-schemas-registry/v2/schemas/0x312e332e362e312e342e312e313338312e332e31322e332e322e332e3738`,
    },

    // Identity
    onboarding: {
      url: `${domain}/users-onboarding/v2`,
      genericName: "users-onboarding-api",
      did: onboardingApiDid,
      kid: onboardingApiKid,
      privateKey: onboardingApiPrivateKey, // only for testing
    },
    "did-new": {
      url: `${domain}/did-registry/v5`,
      genericName: "did-registry-api",
      contract: new ethers.Contract(contractAddresses.didNew, abi.didNew),
    },
    did: {
      url: `${domain}/did-registry/v4`,
      genericName: "did-registry-api",
      contract: new ethers.Contract(contractAddresses.did, abi.did),
    },
    "did-old": {
      url: `${domain}/did-registry/v3`,
      genericName: "did-registry-api",
      contract: new ethers.Contract(contractAddresses.didOld, abi.didOld),
    },
    datahub: {
      url: `${domain}/proxy-data-hub/v3`,
      genericName: "proxy-data-hub-api",
    },

    // Trusted registries
    "tar-new": {
      url: `${domain}/trusted-apps-registry/v4`,
      genericName: "trusted-apps-registry-api",
      contract: new ethers.Contract(contractAddresses.tarNew, abi.tarNew),
    },
    tar: {
      url: `${domain}/trusted-apps-registry/v3`,
      genericName: "trusted-apps-registry-api",
      contract: new ethers.Contract(contractAddresses.tar, abi.tar),
    },
    "tir-new": {
      url: `${domain}/trusted-issuers-registry/v5`,
      genericName: "trusted-issuers-registry-api",
      contract: new ethers.Contract(contractAddresses.tirNew, abi.tirNew),
    },
    tir: {
      url: `${domain}/trusted-issuers-registry/v4`,
      genericName: "trusted-issuers-registry-api",
      contract: new ethers.Contract(contractAddresses.tir, abi.tir),
    },
    "tir-old": {
      url: `${domain}/trusted-issuers-registry/v3`,
      genericName: "trusted-issuers-registry-api",
      contract: new ethers.Contract(contractAddresses.tir, abi.tir),
    },
    "tsr-new": {
      url: `${domain}/trusted-schemas-registry/v3`,
      genericName: "trusted-schemas-registry-api",
      contract: new ethers.Contract(contractAddresses.tsrNew, abi.tsrNew),
    },
    tsr: {
      url: `${domain}/trusted-schemas-registry/v2`,
      genericName: "trusted-schemas-registry-api",
      contract: new ethers.Contract(contractAddresses.tsr, abi.tsr),
    },
    "tpr-new": {
      url: `${domain}/trusted-policies-registry/v3`,
      genericName: "trusted-policies-registry-api",
      contract: new ethers.Contract(contractAddresses.tprNew, abi.tprNew),
    },
    tpr: {
      url: `${domain}/trusted-policies-registry/v2`,
      genericName: "trusted-policies-registry-api",
      contract: new ethers.Contract(contractAddresses.tpr, abi.tpr),
    },

    // Conformance
    "conformance-new": {
      url: `${
        env === "test" ? "https://conformance-test.ebsi.eu" : domain
      }/conformance/v4`,
      did: conformanceApiV4Did,
    },
    conformance: {
      url: `${
        env === "test" ? "https://conformance-test.ebsi.eu" : domain
      }/conformance/v3`,
      did: conformanceApiV3Did,
    },
    conformanceV2: {
      url: `${
        env === "test" ? "https://conformance-test.ebsi.eu" : domain
      }/conformance/v2`,
      did: conformanceApiV2Did,
    },
  };

  const onboardingService = `${domain.replace(
    "api",
    "app"
  )}/users-onboarding/authentication`;
  const domainTarV3Apps = `${domain}/trusted-apps-registry/v3/apps`;
  vitest.resourceApp.kid = setDomain(vitest.resourceApp.kid, domainTarV3Apps);
  vitest.requesterApp.kid = setDomain(vitest.requesterApp.kid, domainTarV3Apps);

  const cassandra = {
    client: new Client({
      contactPoints: (process.env.CASSANDRA_CONTACT_POINTS &&
        process.env.CASSANDRA_CONTACT_POINTS.split(",")) || [
        "cassandradb",
        "localhost",
      ],
      localDataCenter: process.env.CASSANDRA_LOCAL_DATACENTER || "datacenter1",
      keyspace: process.env.CASSANDRA_KEYSPACE || keyspace,
      authProvider:
        process.env.CASSANDRA_USER && process.env.CASSANDRA_PASSWORD
          ? new auth.PlainTextAuthProvider(
              process.env.CASSANDRA_USER,
              process.env.CASSANDRA_PASSWORD
            )
          : undefined,
    }),
    consistency: {
      read:
        ((process.env.CASSANDRA_CONSISTENCY_READ &&
          types.consistencies[
            process.env.CASSANDRA_CONSISTENCY_READ
          ]) as types.consistencies) || types.consistencies.two,
      write:
        ((process.env.CASSANDRA_CONSISTENCY_WRITE &&
          types.consistencies[
            process.env.CASSANDRA_CONSISTENCY_WRITE
          ]) as types.consistencies) || types.consistencies.two,
    },
  };

  return {
    domain,
    contractAddresses,
    api,
    cassandra,
    besuProvider: process.env.BESU_PROVIDER || besuProvider,
    casUrl,
    onboardingService,
    timeoutMining,
    timeoutNotificationConformanceResponse,
    programs,
    vitest,
    vitestNew,
    env,
    dockerServices,
  };
};
