interface JsonRpcResponseObject {
  jsonrpc: string;
  id: string | number;
  result: unknown;
  error?: unknown;
}

export type Visibility = "shared" | "private";

export interface AttributeResponseObject {
  hash?: string;
  storageUri: string;
  did: string;
  visibility?: Visibility;
  sharedWith?: string;
  contentType: string;
  data: string;
  dataLabel?: string;
  proof?: unknown;
}

export interface AttributeCassandraModel {
  hash: string;
  did: string;
  visibility: Visibility;
  shared_with: string;
  content_type: string;
  data: string;
  data_label: string;
}

export interface AxiosResponseJsonRpc {
  status: number;
  data: JsonRpcResponseObject;
}

export interface CassandraResponse {
  rows: unknown[];
  pageState: string;
}
