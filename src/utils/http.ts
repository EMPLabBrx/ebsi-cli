import axios, { AxiosError, AxiosResponse, Method } from "axios";
import https from "https";
import chalk from "chalk";
import FormData from "form-data";
import * as httpsProxyAgent from "https-proxy-agent";
import * as dotenv from "dotenv";
import { print } from "./print.js";
import { UnknownObject } from "../interfaces/index.js";

dotenv.config();

export function isStreaming(opts: { responseType?: string }): boolean {
  return opts && opts.responseType === "stream";
}

export function printResponse(
  response: AxiosResponse,
  iniTime: number,
  options?: UnknownObject
): void {
  const color = response.status < 400 ? chalk.green : chalk.red;
  const colorBold = response.status < 400 ? chalk.green.bold : chalk.red.bold;
  print(color, `\n${Date.now() - iniTime} milliseconds`);
  print(colorBold, `Response HTTP Status ${response.status}`);
  print(chalk.gray, response.headers);
  print(color, "Data:");
  if (!isStreaming(options)) print(color, response.data);
}

function isResolvingToIP(url: string) {
  return (
    new URL(url).host === process.env.HTTP_RESOLVE_HOST &&
    process.env.HTTP_RESOLVE_IP
  );
}

function getResolveDetails(url: string) {
  if (!isResolvingToIP(url)) return "";
  return `--resolve ${process.env.HTTP_RESOLVE_HOST}:${process.env.HTTP_RESOLVE_IP}`;
}

async function useAxios<T = unknown>(
  method: Method,
  url: string,
  data: unknown,
  opts: Record<string, unknown>
): Promise<AxiosResponse<T>> {
  const iniTime = Date.now();
  let url2 = url;
  let resolvingToIP = false;
  if (isResolvingToIP(url)) {
    url2 = url.replace(
      process.env.HTTP_RESOLVE_HOST,
      process.env.HTTP_RESOLVE_IP
    );
    if (opts && opts.headers) {
      // eslint-disable-next-line no-param-reassign
      (opts.headers as { Host: string }).Host = process.env.HTTP_RESOLVE_HOST;
    }
    resolvingToIP = true;
  }
  try {
    const response = await axios({
      method,
      url: url2,
      data,
      proxy: false,
      ...(resolvingToIP && {
        headers: {
          Host: process.env.HTTP_RESOLVE_HOST,
        },
      }),
      httpsAgent: new https.Agent({
        rejectUnauthorized: false,
        ...(resolvingToIP && {
          servername: process.env.HTTP_RESOLVE_HOST,
        }),
      }),
      ...(process.env.PROXY && {
        httpsAgent: new httpsProxyAgent.HttpsProxyAgent(process.env.PROXY),
      }),

      validateStatus: (status) => {
        return status >= 200 && status <= 302;
      },
      maxRedirects: 0,
      ...opts,
    });
    printResponse(response, iniTime, opts);
    return response;
  } catch (error) {
    const axiosError = error as AxiosError<string | UnknownObject>;
    if (axiosError.isAxiosError && axiosError.response) {
      printResponse(axiosError.response, iniTime, opts);
      if (isStreaming(opts))
        return axiosError.response as unknown as AxiosResponse<T>;
      const { data: dataR, status } = axiosError.response;
      const dataString =
        typeof dataR === "string" ? dataR : JSON.stringify(dataR);
      const message = `Request failed with status code ${status}: ${dataString}`;
      throw new Error(message);
    }
    print(chalk.red, (error as Error).message);
    throw error;
  }
}

export const httpCall = {
  get: async <T>(url: string, options = {}): Promise<AxiosResponse> => {
    print(chalk.blue.bold, `GET ${url} ${getResolveDetails(url)}`);
    print(chalk.gray, options);
    return useAxios<T>("GET", url, null, options);
  },
  post: async <T>(
    url: string,
    data: unknown,
    options = {}
  ): Promise<AxiosResponse<T>> => {
    print(chalk.blue.bold, `POST ${url} ${getResolveDetails(url)}`);
    print(chalk.gray, options);
    print(chalk.blue, "Data:");
    if (data instanceof FormData) {
      print(
        chalk.blue,
        `${
          // eslint-disable-next-line no-underscore-dangle
          (data as unknown as { _streams: string[] })._streams[0]
        }\n... binary data ...`
      );
    } else {
      print(chalk.blue, data);
    }
    return useAxios("POST", url, data, options);
  },
  put: async <T>(
    url: string,
    data: unknown,
    options = {}
  ): Promise<AxiosResponse<T>> => {
    print(chalk.blue.bold, `PUT ${url} ${getResolveDetails(url)}`);
    print(chalk.gray, options);
    print(chalk.blue, "Data:");
    print(chalk.blue, data);
    return useAxios("PUT", url, data, options);
  },
  patch: async <T>(
    url: string,
    data: unknown,
    options = {}
  ): Promise<AxiosResponse<T>> => {
    print(chalk.blue.bold, `PATCH ${url} ${getResolveDetails(url)}`);
    print(chalk.gray, options);
    print(chalk.blue, "Data:");
    print(chalk.blue, data);
    return useAxios("PATCH", url, data, options);
  },
  delete: async <T>(url: string, options = {}): Promise<AxiosResponse<T>> => {
    print(chalk.blue.bold, `DELETE ${url} ${getResolveDetails(url)}`);
    print(chalk.gray, options);
    return useAxios("DELETE", url, null, options);
  },
};

export default httpCall;
