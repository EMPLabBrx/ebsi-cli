import fs from "fs";
import { execCommand } from "../app.js";
import { loadConfig } from "../config.js";

const config = loadConfig();
const { admin } = config.programs;

const [jsonFile] = process.argv.slice(2);

const nodeKeys = JSON.parse(fs.readFileSync(jsonFile, "utf8")) as {
  appAdmin: string;
  apps: {
    name: string;
    dockerService: string;
    publicKeyPemBase64: string;
  }[];
};

(async () => {
  const errors = [];
  const skipped = [];
  const success = [];

  await execCommand(
    `using user ES256K did1 ${admin.privateKey} ${admin.did} ${admin.keyId}`
  );
  await execCommand("tokenAdmin: authorisation-new siop");
  await execCommand("using token tokenAdmin");

  for (let i = 0; i < nodeKeys.apps.length; i += 1) {
    const app = nodeKeys.apps[i];

    let action: string;
    let registeredApp: { publicKeys: string[] };
    try {
      action = `insert app ${app.name}`;
      try {
        registeredApp = await execCommand(`tar-new get /apps/${app.name}`);
        skipped.push(`app ${app.name} already exists`);
      } catch (error) {
        // not found
        if (!config.dockerServices.includes(app.dockerService)) {
          throw new Error(
            `Service '${app.dockerService}' not in the DOCKER_SERVICES list`
          );
        }

        await execCommand(`tar-new insertApp ${app.name} ${nodeKeys.appAdmin}`);
        success.push(`app ${app.name} registered`);
        registeredApp = { publicKeys: [] };
      }

      action = `register public key of ${app.name}`;
      if (registeredApp.publicKeys.includes(app.publicKeyPemBase64)) {
        skipped.push(`public key for ${app.name} already exists`);
      } else {
        await execCommand(
          `tar-new insertAppPublicKey ${app.name} ${app.publicKeyPemBase64}`
        );
        success.push(`public key for ${app.name} registered`);
      }
    } catch (error) {
      errors.push({
        action,
        error: (error as Error).message,
      });
    }
  }
  console.log(`\n\nApp admin: ${nodeKeys.appAdmin}`);
  console.log(`\nSuccess: ${success.length}`);
  console.log(success);
  console.log(`\nSkipped: ${skipped.length}`);
  console.log(skipped);
  console.log(`\nErrors: ${errors.length}`);
  console.log(errors);
})()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.log(error);
    process.exit(1);
  });
