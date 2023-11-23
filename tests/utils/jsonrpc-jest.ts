import { expect } from "vitest";
import { UnknownObject } from "../../src/interfaces/index.js";
import { VitestMockConsole } from "./interface.js";
import { consoleOutput } from "./utils.js";

export function expectResponseSendTransaction<T = UnknownObject>(
  mockConsole: VitestMockConsole,
  response: unknown
): T {
  // response building the transaction
  let dataString = consoleOutput<string>(mockConsole, 9, false);
  expect(dataString).toBeJsonString();
  const dataBuild = JSON.parse(dataString) as unknown;
  expect(dataBuild).toStrictEqual({
    jsonrpc: "2.0",
    id: expect.any(Number) as number,
    result: {
      from: expect.any(String) as string,
      to: expect.any(String) as string,
      data: expect.any(String) as string,
      value: "0x0",
      nonce: expect.any(String) as string,
      chainId: expect.any(String) as string,
      gasLimit: expect.any(String) as string,
      gasPrice: "0x0",
    },
  });

  // signing the transaction
  dataString = consoleOutput<string>(mockConsole, 13, false);
  expect(dataString).toStrictEqual(expect.any(String) as string);

  // response after sending the transaction signed
  dataString = consoleOutput<string>(mockConsole, 23, false);
  expect(dataString).toBeJsonString();
  const data = JSON.parse(dataString) as T;
  expect(data).toStrictEqual(response);
  return data;
}

export function expectTransaction(
  mockConsole: VitestMockConsole
): string | UnknownObject {
  expectResponseSendTransaction(mockConsole, {
    jsonrpc: "2.0",
    id: expect.any(Number) as number,
    result: expect.any(String) as string,
  });

  // waiting to be mined
  const dataString = consoleOutput<string>(mockConsole, -4, false);
  expect(dataString).toBeJsonString();
  const data = JSON.parse(dataString) as unknown;
  expect(data).toStrictEqual({
    jsonrpc: "2.0",
    id: expect.any(Number) as number,
    result: expect.objectContaining({
      blockNumber: expect.any(String) as string,
      status: expect.any(String) as string,
    }) as unknown,
  });

  return consoleOutput(mockConsole, -1);
}

export function expectRevertedTransaction(
  mockConsole: VitestMockConsole,
  revertReason: string
): string | UnknownObject {
  expectResponseSendTransaction(mockConsole, {
    jsonrpc: "2.0",
    id: expect.any(Number) as number,
    result: expect.any(String) as string,
  });

  // waiting to be mined
  const dataString = consoleOutput<string>(mockConsole, -1, false);
  expect(dataString).toStrictEqual(
    expect.stringContaining("Transaction failed: Status 0x0. Revert reason:")
  );
  expect(dataString).toStrictEqual(expect.stringContaining(revertReason));

  return dataString.split("\n")[0];
}
