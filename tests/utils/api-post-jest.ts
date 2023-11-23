import { expect } from "vitest";
import {
  JsonRpcResponse,
  PaginatedListCassandra,
  UnknownObject,
} from "../../src/interfaces/index.js";
import { VitestMockConsole } from "./interface.js";
import { consoleOutput } from "./utils.js";

export function expectStorageCollection<T = UnknownObject>(
  mockConsole: VitestMockConsole
): PaginatedListCassandra<T> {
  const dataString = consoleOutput<string>(mockConsole, -1, false);
  expect(dataString).toBeJsonString();
  const data = JSON.parse(dataString) as PaginatedListCassandra<T>;
  expect(data).toStrictEqual(
    expect.objectContaining({
      self: expect.any(String) as string,
      items: expect.arrayContaining([]) as T[],
      pageSize: expect.any(Number) as number,
      links: expect.objectContaining({}) as { next: string },
    })
  );
  return data;
}

export function expectStorageJsonrpcResponse<T = UnknownObject>(
  mockConsole: VitestMockConsole
): JsonRpcResponse<T> {
  const dataString = consoleOutput<string>(mockConsole, -1, false);
  expect(dataString).toBeJsonString();
  const data = JSON.parse(dataString) as JsonRpcResponse<T>;
  expect(data).toStrictEqual({
    id: expect.any(Number) as number,
    jsonrpc: "2.0",
    result: expect.objectContaining({
      rows: expect.arrayContaining([]) as T[],
    }) as unknown,
  });
  return data;
}

export function expectPostStatus(
  mockConsole: VitestMockConsole,
  status: number
): void {
  const responseString = consoleOutput<string>(mockConsole, 5);
  expect(responseString).toBe(
    `Response HTTP Status ${Number(status).toString()}`
  );
}
