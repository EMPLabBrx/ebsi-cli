export interface RecordLink {
  recordId: string;
  href: string;
}

export interface RecordResponseObject {
  ownerIds: string[];
  revokedOwnerIds: string[];
  firstVersionTimestamps: string[];
  lastVersionTimestamps: string[];
  totalVersions: number;
}

export interface VersionLink {
  versionId: number;
  href: string;
}

export interface InfoObject {
  [x: string]: unknown;
}

export interface RecordVersionResponseObject {
  hashes: string[];
  info: InfoObject[];
}
