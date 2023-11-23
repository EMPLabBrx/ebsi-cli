import chalk from "chalk";
import * as dotenv from "dotenv";

dotenv.config();
const noChalk = process.env.NO_CHALK === "true";

export function print(theme: chalk.Chalk, data: unknown): void {
  if (process.env.NO_HTTP_LOGS === "true") return;
  let dataString: string;
  if (typeof data === "string") {
    dataString = data;
  } else {
    try {
      dataString = JSON.stringify(data, null, 2);
    } catch (error) {
      console.log(data);
      console.log("Error when trying to stringify the previous object");
      throw error;
    }
  }
  if (noChalk) console.log(dataString);
  else console.log(theme(dataString));
}

export function red(data: unknown): void {
  print(chalk.red, data);
}

export function redBold(data: unknown): void {
  print(chalk.red, data);
}

export function green(data: unknown): void {
  print(chalk.green, data);
}

export function greenBold(data: unknown): void {
  print(chalk.green, data);
}

export function blue(data: unknown): void {
  print(chalk.blue, data);
}

export function blueBold(data: unknown): void {
  print(chalk.blue, data);
}

export function yellow(data: unknown): void {
  print(chalk.yellow, data);
}

export function yellowBold(data: unknown): void {
  print(chalk.yellow, data);
}

export function cyan(data: unknown): void {
  print(chalk.cyan, data);
}

export function cyanBold(data: unknown): void {
  print(chalk.cyan.bold, data);
}
