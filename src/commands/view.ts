import { ethers } from "ethers";
import { KeyPairJwk, multibaseEncode, yellow } from "../utils/index.js";
import { Context } from "../interfaces/context.js";

export function view(inputs: string[], context: Context): unknown {
  const [id] = inputs;
  switch (id) {
    case "transactionInfo": {
      const { contract, method, receipt } = context.transactionInfo;
      if (
        (contract !== "timestamp" && contract !== "timestamp-new") ||
        method !== "timestampRecordHashes" ||
        !receipt ||
        Number(receipt.status) !== 1
      ) {
        yellow(context.transactionInfo.build.info.title);
        yellow(context.transactionInfo.build.info.data);
        return context.transactionInfo;
      }

      // custom info for timestampRecordHashes which involves
      // the calculation of timestampId from the blockNumber
      const [hashValue] = (
        context.transactionInfo.build.param as { hashValues: string[] }
      ).hashValues;
      const recordId = ethers.utils.sha256(
        ethers.utils.defaultAbiCoder.encode(
          ["address", "uint256", "bytes"],
          [receipt.from, receipt.blockNumber, hashValue]
        )
      );
      const multibase64urlRecordId = multibaseEncode("base64url", recordId);
      context.transactionInfo.build.info.data = {
        blockNumber: receipt.blockNumber,
        recordId,
        multibase64urlRecordId,
        hashValue,
      };
      yellow(context.transactionInfo.build.info.title);
      yellow(context.transactionInfo.build.info.data);
      return context.transactionInfo;
    }
    case "token": {
      yellow(context.token);
      return context.token;
    }
    case "oauth2token": {
      yellow(context.oauth2token);
      return context.oauth2token;
    }
    case "user": {
      const didDocument = context.client.generateDidDocument();
      yellow(`DID Document: \n${JSON.stringify(didDocument)}`);
      Object.keys(context.client.keys).forEach((alg) => {
        const { privateKeyJwk } = context.client.keys[alg] as KeyPairJwk;
        const privateKeyJwkBase64 = Buffer.from(
          JSON.stringify(privateKeyJwk)
        ).toString("base64");
        yellow(`\nprivateKeyJwk${alg} (base64): ${privateKeyJwkBase64}`);
      });
      yellow(
        `\nkeys (base64): \n${context.client.privateKeysBase64()}\n\nUser:`
      );
      yellow(context.client.toJSON());
      return context.client;
    }
    case "app": {
      yellow(context.trustedApp);
      return context.trustedApp;
    }
    default: {
      yellow(id);
      return id;
    }
  }
}

export default view;
