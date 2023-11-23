import Joi from "joi";
import { httpCall, jsonrpcBody, red, yellow } from "../utils/index.js";
import { Context } from "../interfaces/context.js";
import {
  JsonRpcResponse,
  Receipt,
  UnknownObject,
} from "../interfaces/index.js";
import { ConfigApi } from "../config.js";
import { buildParam } from "../buildParam/index.js";
import { compute } from "./compute.js";
import { view } from "./view.js";

export const smartContractApiList = [
  "timestamp",
  "timestamp-new",
  "did",
  "did-old",
  "did-new",
  "tar",
  "tar-new",
  "tir",
  "tir-old",
  "tir-new",
  "tsr",
  "tsr-new",
  "tpr",
  "tpr-new",
];

export async function ledgerGet(inputs: string[], context: Context) {
  const apiUrl = context.config.api["ledger-new"].url;
  const urlPath = inputs.join("");
  const url = urlPath.startsWith("http") ? urlPath : `${apiUrl}${urlPath}`;
  const response = await httpCall.get(url, context.httpOpts);
  return response.data as unknown;
}

export async function ledgerGetBlock(
  inputs: string[],
  useProxy: boolean,
  context: Context
) {
  const apiUrl = useProxy
    ? context.config.besuProvider
    : `${context.config.api["ledger-new"].url}/blockchains/besu`;
  const body = jsonrpcBody("eth_getBlockByNumber", [inputs[0], true]);
  const response = await httpCall.post<JsonRpcResponse>(
    apiUrl,
    body,
    context.httpOpts
  );
  return response.data.result;
}

export async function ledgerGetTransactionCount(
  inputs: string[],
  useProxy: boolean,
  context: Context
) {
  const apiUrl = useProxy
    ? context.config.besuProvider
    : `${context.config.api["ledger-new"].url}/blockchains/besu`;
  const body = jsonrpcBody("eth_getTransactionCount", [inputs[0], "latest"]);
  const response = await httpCall.post<JsonRpcResponse>(
    apiUrl,
    body,
    context.httpOpts
  );
  return response.data.result;
}

export async function ledgerGetChainId(
  inputs: string[],
  useProxy: boolean,
  context: Context
) {
  const apiUrl = useProxy
    ? context.config.besuProvider
    : `${context.config.api["ledger-new"].url}/blockchains/besu`;
  const body = jsonrpcBody("net_version", []);
  const response = await httpCall.post<JsonRpcResponse>(
    apiUrl,
    body,
    context.httpOpts
  );
  return response.data.result;
}

export async function ledgerGetTransaction(
  inputs: string[],
  useProxy: boolean,
  context: Context
) {
  const apiUrl = useProxy
    ? context.config.besuProvider
    : `${context.config.api["ledger-new"].url}/blockchains/besu`;
  const body = jsonrpcBody("eth_getTransactionByHash", [inputs[0]]);
  const response = await httpCall.post<JsonRpcResponse>(
    apiUrl,
    body,
    context.httpOpts
  );
  return response.data.result;
}

export async function ledgerGetTransactionReceipt(
  inputs: string[],
  useProxy: boolean,
  context: Context
) {
  const apiUrl = useProxy
    ? context.config.besuProvider
    : `${context.config.api["ledger-new"].url}/blockchains/besu`;
  const body = jsonrpcBody("eth_getTransactionReceipt", [inputs[0]]);
  const response = await httpCall.post<JsonRpcResponse | string>(
    apiUrl,
    body,
    context.httpOpts
  );
  const receipt = (response.data as JsonRpcResponse<Receipt>).result;
  if (receipt && Number(receipt.status) !== 1) {
    const message = `Transaction failed: Status ${
      receipt.status
    }. Revert reason: ${
      receipt.revertReason
        ? Buffer.from(receipt.revertReason.slice(138), "hex")
            .toString()
            .replace(/[^a-zA-Z0-9:\-' ]/g, "")
        : ""
    }`;
    red(message);
    throw new Error(message);
  }
  return receipt;
}

// TODO:  export this function when the api is available in
// all environments
async function waitToBeMined(
  txId: string,
  useProxy: boolean,
  context: Context
): Promise<Receipt> {
  let mined = false;
  let receipt: Receipt = null;

  yellow("Waiting to be mined...");
  const iniTime = Date.now();
  let diffTime = 0;
  while (!mined && diffTime <= context.config.timeoutMining) {
    await new Promise((resolve) => {
      setTimeout(resolve, 5000);
    });
    console.log(
      `==> ${
        useProxy ? "proxyledger" : "ledger-new"
      } getTransactionReceipt ${txId}`
    );
    receipt = await ledgerGetTransactionReceipt([txId], useProxy, context);
    mined = !!receipt;
    diffTime = Date.now() - iniTime;
  }

  if (!mined && diffTime > context.config.timeoutMining) {
    throw new Error(
      `${context.config.timeoutMining} milliseconds timeout. Transaction ${txId} is still waiting to be mined`
    );
  }

  return receipt;
}

export async function ledgerSendTransaction(
  inputs: string[],
  useProxy: boolean,
  context: Context
) {
  const apiUrl = useProxy
    ? context.config.besuProvider
    : `${context.config.api["ledger-new"].url}/blockchains/besu`;
  const [sgnTx] = inputs;
  Joi.assert(sgnTx, Joi.string());
  const body = jsonrpcBody("eth_sendRawTransaction", [sgnTx]);
  const response = await httpCall.post<JsonRpcResponse<string>>(
    apiUrl,
    body,
    context.httpOpts
  );
  context.transactionInfo.txId = response.data.result;
  context.transactionInfo.receipt = await waitToBeMined(
    response.data.result,
    useProxy,
    context
  );
  return context.transactionInfo.receipt;
}

export async function ledgerCallSmartContract(
  contractName: string,
  inputs: (string | UnknownObject)[],
  useProxy: boolean,
  context: Context
) {
  const { contract } = context.config.api[contractName] as ConfigApi;

  const [m, ...args] = inputs as [string, ...(string | UnknownObject)[]];
  let method = m;
  Joi.assert(method, Joi.string());

  // check if the method is just to build the unsigned transaction
  if (method.startsWith("build-")) {
    method = method.replace("build-", "");
    const build = await buildParam(contractName, method, context.client, args);
    const params = Object.keys(build.param).map((key) => build.param[key]);
    if (build.method) method = build.method;
    const data = contract.interface.encodeFunctionData(method, params);

    yellow(build.info.title);
    yellow(build.info.data);

    context.transactionInfo = {
      contract: contractName,
      method,
      build,
    };

    return {
      from: context.client.ethWallet.address,
      to: contract.address,
      data,
      value: "0x0",
      nonce: await ledgerGetTransactionCount(
        [context.client.ethWallet.address],
        useProxy,
        context
      ),
      chainId: `0x${Number(
        await ledgerGetChainId([], useProxy, context)
      ).toString(16)}`,
      gasLimit: "0xFFFFFF",
      gasPrice: "0x0",
    };
  }

  // build, sign and send
  const cmd = useProxy ? "proxyledger" : "ledger-new";

  console.log(
    `==> ${cmd} built-${method} ${args
      .map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg)))
      .join(" ")}`
  );
  const uTx = (await ledgerCallSmartContract(
    contractName,
    [`build-${method}`, ...args],
    useProxy,
    context
  )) as UnknownObject;

  console.log(`==> compute signTransaction ${JSON.stringify(uTx)}`);
  const sgnTx = (await compute("signTransaction", [uTx], context)) as string;

  console.log(`==> ${cmd} sendTransaction ${sgnTx}`);
  const receipt = await ledgerSendTransaction([sgnTx], useProxy, context);

  await view(["transactionInfo"], context);
  return receipt;
}

export async function ledgerV4(
  method: string,
  inputs: (string | UnknownObject)[],
  useProxy: boolean,
  context: Context
): Promise<unknown> {
  if (smartContractApiList.includes(method)) {
    return ledgerCallSmartContract(method, inputs, useProxy, context);
  }

  switch (method) {
    case "get": {
      return ledgerGet(inputs as string[], context);
    }
    case "getBlock": {
      return ledgerGetBlock(inputs as string[], useProxy, context);
    }
    case "getTransactionCount": {
      return ledgerGetTransactionCount(inputs as string[], useProxy, context);
    }
    case "getChainId": {
      return ledgerGetChainId(inputs as string[], useProxy, context);
    }
    case "getTransaction": {
      return ledgerGetTransaction(inputs as string[], useProxy, context);
    }
    case "getTransactionReceipt": {
      return ledgerGetTransactionReceipt(inputs as string[], useProxy, context);
    }
    case "sendTransaction": {
      return ledgerSendTransaction(inputs as string[], useProxy, context);
    }
    default:
      red(`Invalid method '${method}'`);
      return 0;
  }
}
