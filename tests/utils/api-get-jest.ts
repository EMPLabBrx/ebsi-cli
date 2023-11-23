import { expect } from "vitest";
import { PaginatedList, UnknownObject } from "../../src/interfaces/index.js";
import { VitestMockConsole } from "./interface.js";
import { consoleOutput } from "./utils.js";

export function expectCollection<T = UnknownObject>(
  mockConsole: VitestMockConsole
): PaginatedList<T> {
  const dataString = consoleOutput<string>(mockConsole, -1, false);
  expect(dataString).toBeJsonString();
  const data = JSON.parse(dataString) as PaginatedList<T>;
  expect(data).toStrictEqual({
    self: expect.any(String) as string,
    items: expect.arrayContaining([]) as T[],
    total: expect.any(Number) as number,
    pageSize: expect.any(Number) as number,
    links: {
      first: expect.any(String) as string,
      prev: expect.any(String) as string,
      next: expect.any(String) as string,
      last: expect.any(String) as string,
    },
  });
  return data;
}

export function expectResponse<T = UnknownObject>(
  mockConsole: VitestMockConsole,
  resource: unknown
): T {
  const dataString = consoleOutput<string>(mockConsole, -1, false);
  expect(dataString).toBeJsonString();
  const data = JSON.parse(dataString) as T;
  expect(data).toStrictEqual(resource);
  return data;
}

export function expectStatus(
  mockConsole: VitestMockConsole,
  status: number
): void {
  const responseString = consoleOutput<string>(mockConsole, 3, false);
  expect(responseString).toBe(
    `Response HTTP Status ${Number(status).toString()}`
  );
}
