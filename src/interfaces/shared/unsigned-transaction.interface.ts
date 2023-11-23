export interface UnsignedTransaction {
  from: string;
  to: string;
  data: string;
  nonce: string;
  chainId: string;
  gasLimit: string;
  gasPrice: string;
  value: string;
}
