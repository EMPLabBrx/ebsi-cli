import { SpyInstance } from "vitest";

export type VitestMockConsole = SpyInstance<
  [message?: string, ...optionalParams: unknown[]]
>;
