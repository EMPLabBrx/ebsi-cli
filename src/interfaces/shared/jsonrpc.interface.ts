import { ethers } from "ethers";

export type JsonRpcParam = {
  from: string;
  [x: string]: unknown;
};

export interface JsonRpcResponseObject {
  jsonrpc: string;
  id: string | number;
  result: unknown;
  error?: unknown;
}

export interface JsonRpcResponse<T = unknown> {
  jsonrpc: string;
  id: string | number;
  result: T;
  error?: unknown;
}

export interface JsonRpcRequest {
  jsonrpc: string;
  id: string | number;
  method: string;
  params: unknown[];
}

export interface SupertestJsonRpcResponse {
  status: number;
  body: JsonRpcResponseObject;
}

export interface ParamSignedTransaction {
  protocol: string;
  unsignedTransaction: ethers.UnsignedTransaction;
  r: string;
  s: string;
  v: string;
  signedRawTransaction: string;
}

export interface Receipt {
  blockNumber: string;
  from: string;
  status: string;
  revertReason?: string;
}
