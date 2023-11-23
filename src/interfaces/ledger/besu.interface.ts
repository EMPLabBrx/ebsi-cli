export interface BesuResponseObject {
  jsonrpc: string;
  id: string | number;
  result?: unknown;
  error?: unknown;
}
