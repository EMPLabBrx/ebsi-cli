export interface PolicyResponseObject {
  policyId: string;
  policy: string;
  hash: string;
}

export interface PolicyLink {
  policyId: string;
  href: string;
}

export type PolicyRevisions = {
  items: {
    policyId: string;
    policy: string;
    hash: string;
  }[];
  total: number;
};
