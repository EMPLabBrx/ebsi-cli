import { UnknownObject } from "../../src/interfaces/index.js";
import { VitestMockConsole } from "./interface.js";

export function consoleOutput<T = UnknownObject>(
  mockConsole: VitestMockConsole,
  index: number,
  tryJSON = true
): string | T {
  const len = mockConsole.mock.calls.length;
  let id = index;
  if (index >= 0) id = index;
  else id = len + index;
  if (id >= len || id < 0) {
    const lastLog =
      len > 0 ? ` Last log ${mockConsole.mock.calls[len - 1][0]}` : "";
    throw new Error(`Invalid index ${index}. Length: ${len}. ${lastLog}`);
  }
  const dataString = mockConsole.mock.calls[id][0];
  if (!tryJSON) return dataString;
  try {
    return JSON.parse(dataString) as T;
  } catch (e) {
    return dataString;
  }
}

export default consoleOutput;
