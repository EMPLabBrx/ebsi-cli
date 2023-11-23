interface AttributeObject {
  hash: string;
  body: string;
}

export interface IssuerResponseObject {
  did: string;
  attributes: AttributeObject[];
}
