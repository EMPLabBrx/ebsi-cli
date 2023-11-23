export interface TimestampLink {
  timestampId: string; // multi-base64url encoded sha256(hash)
  href: string;
}

export interface TimestampResponseObject {
  hash: string; // multi-hash (base64 multi-encoded)
  timestampedBy: string;
  blockNumber: number;
  data: string;
  transactionHash: string;
}
