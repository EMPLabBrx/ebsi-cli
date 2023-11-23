import Joi from "joi";
import { BuildParamResponse } from "../interfaces/shared/index.js";
import { Client } from "../utils/Client.js";

export function buildParamTprV2(
  method: string,
  client: Client,
  inputs: unknown[]
): BuildParamResponse {
  switch (method) {
    case "insertUserAttributes": {
      const [address, attributes] = inputs as [string, string[]];
      Joi.assert(address, Joi.string());
      Joi.assert(attributes, Joi.array().items(Joi.string()));

      return {
        info: {
          title: `Insert User Attribute`,
          data: { address, attributes },
        },
        param: { address, attributes },
      };
    }
    case "deleteUserAttribute": {
      const [address, attributeName] = inputs as string[];
      Joi.assert(address, Joi.string());
      Joi.assert(attributeName, Joi.string());

      return {
        info: {
          title: `Delete User Attribute`,
          data: { address, attributeName },
        },
        param: { address, attributeName },
      };
    }

    case "insertPolicy": {
      const [policyName, descriptionInput] = inputs as [
        string,
        string | string[]
      ];
      Joi.assert(policyName, Joi.string());
      const description = Array.isArray(descriptionInput)
        ? descriptionInput[0]
        : descriptionInput;

      return {
        info: {
          title: "Insert Policy",
          data: { policyName, description },
        },
        param: { policyName, description },
      };
    }

    case "updatePolicy": {
      const [policyIdorName, descriptionInput] = inputs as [
        string,
        string | string[]
      ];
      Joi.assert(policyIdorName, Joi.string());
      const description = Array.isArray(descriptionInput)
        ? descriptionInput[0]
        : descriptionInput;

      const isId = !Number.isNaN(Number(policyIdorName));
      const param = {
        ...(isId && { policyId: policyIdorName }),
        ...(!isId && { policyName: policyIdorName }),
        description,
      };

      return {
        info: {
          title: "Insert Policy",
          data: param,
        },
        param,
      };
    }

    case "deactivatePolicy":
    case "activatePolicy": {
      const [policyIdorName] = inputs as string[];
      Joi.assert(policyIdorName, Joi.string());

      const isId = !Number.isNaN(Number(policyIdorName));
      const policyRef = {
        ...(isId && { policyId: policyIdorName }),
        ...(!isId && { policyName: policyIdorName }),
      };

      return {
        info: { title: "Deactivate Policy", data: policyRef },
        param: policyRef,
        method: isId ? `${method}(uint256)` : `${method}(string)`,
      };
    }
    default:
      throw new Error(`Invalid method '${method}'`);
  }
}

export default buildParamTprV2;
