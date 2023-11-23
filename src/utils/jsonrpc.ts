import { ethers } from "ethers";
import { JsonRpcRequest, ParamSignedTransaction } from "../interfaces/index.js";

export function jsonrpcBody(method: string, params: unknown[]): JsonRpcRequest {
  return {
    jsonrpc: "2.0",
    method,
    params,
    id: Math.ceil(Math.random() * 1000),
  };
}

export function formatEthersUnsignedTransaction(
  unsignedTransaction: ethers.UnsignedTransaction
): ethers.UnsignedTransaction {
  const chainId = Number(unsignedTransaction.chainId);
  return {
    to: unsignedTransaction.to,
    data: unsignedTransaction.data,
    value: unsignedTransaction.value,
    nonce: Number(unsignedTransaction.nonce),
    chainId: Number.isNaN(chainId) ? undefined : chainId,
    gasLimit: unsignedTransaction.gasLimit,
    gasPrice: unsignedTransaction.gasPrice,
  };
}

export function paramSignedTransaction(
  tx: ethers.Transaction,
  sgnTx: string
): ParamSignedTransaction {
  const { r, s, v } = ethers.utils.parseTransaction(sgnTx);
  return {
    protocol: "eth",
    unsignedTransaction: tx,
    r,
    s,
    v: `0x${Number(v).toString(16)}`,
    signedRawTransaction: sgnTx,
  };
}
