#!/usr/bin/env node

// eslint-disable-next-line import/extensions
import { main } from "../dist/app.js";

main()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.log(error);
    process.exit(1);
  });
