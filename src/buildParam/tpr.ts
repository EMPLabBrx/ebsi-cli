import Joi from "joi";
import { BuildParamResponse } from "../interfaces/shared/index.js";
import { Client } from "../utils/Client.js";

const BOOL_ZERO = `0x${"00".repeat(32)}`;
const BOOL_ONE = `0x${"00".repeat(31)}01`;
const AND_OPERATION = 0;
const EQUAL = 0;
const TYPE_BOOLEAN = 5;

export function buildParamTpr(
  method: string,
  client: Client,
  inputs: unknown[]
): BuildParamResponse {
  switch (method) {
    case "insertUserAttributes": {
      const [address, attributeNames, valuesBool] = inputs as [
        string,
        string[],
        boolean[]
      ];
      Joi.assert(address, Joi.string());
      Joi.assert(attributeNames, Joi.array().items(Joi.string()));
      Joi.assert(valuesBool, Joi.array().items(Joi.boolean()));

      const attributeValues = valuesBool.map((v) => (v ? BOOL_ONE : BOOL_ZERO));
      return {
        info: {
          title: `Insert User Attribute`,
          data: { address, attributeNames, attributeValues, valuesBool },
        },
        param: { address, attributeNames, attributeValues },
      };
    }
    case "updateUserAttribute": {
      const [address, attributeName, valueBool] = inputs as string[];
      Joi.assert(address, Joi.string());
      Joi.assert(attributeName, Joi.string());
      Joi.assert(valueBool, Joi.string().valid("true", "false"));

      const attributeValue = valueBool ? BOOL_ONE : BOOL_ZERO;
      return {
        info: {
          title: `Update User Attribute`,
          data: { address, attributeName, attributeValue, valueBool },
        },
        param: { address, attributeName, attributeValue },
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
      const [policyName, valueBool, descriptionInput] = inputs as [
        string,
        string,
        string | string[]
      ];
      Joi.assert(policyName, Joi.string());
      Joi.assert(valueBool, Joi.string().valid("true", "false"));

      const opType = AND_OPERATION;
      const policyConditions = [
        {
          name: policyName,
          attributeName: policyName,
          value: valueBool ? BOOL_ONE : BOOL_ZERO,
          attributeOperation: EQUAL,
          typeOfValue: TYPE_BOOLEAN,
        },
      ];
      const description = Array.isArray(descriptionInput)
        ? descriptionInput[0]
        : descriptionInput;

      return {
        info: {
          title: "Insert Policy",
          data: { opType, policyConditions, policyName, description },
        },
        param: { opType, policyConditions, policyName, description },
      };
    }
    case "addPolicyConditions": {
      const [policyIdorName, conditionName, valueBool] = inputs as string[];
      Joi.assert(policyIdorName, Joi.string());
      Joi.assert(conditionName, Joi.string());
      Joi.assert(valueBool, Joi.string().valid("true", "false"));

      const isId = !Number.isNaN(Number(policyIdorName));
      const policyRef = {
        ...(isId && { policyId: policyIdorName }),
        ...(!isId && { policyName: policyIdorName }),
      };
      const policyConditions = [
        {
          name: conditionName,
          attributeName: conditionName,
          value: valueBool ? BOOL_ONE : BOOL_ZERO,
          attributeOperation: EQUAL,
          typeOfValue: TYPE_BOOLEAN,
        },
      ];

      return {
        info: {
          title: "Add Policy Condition",
          data: { ...policyRef, policyConditions },
        },
        param: { ...policyRef, policyConditions },
        method: isId
          ? "addPolicyConditions(uint256,(string,string,uint8,bytes,uint8)[])"
          : "addPolicyConditions(string,(string,string,uint8,bytes,uint8)[])",
      };
    }
    case "deletePolicyCondition": {
      const [policyIdorName, policyConditionId] = inputs as string[];
      Joi.assert(policyIdorName, Joi.string());
      Joi.assert(policyConditionId, Joi.string());

      const isId = !Number.isNaN(Number(policyIdorName));
      const policyRef = {
        ...(isId && { policyId: policyIdorName }),
        ...(!isId && { policyName: policyIdorName }),
      };

      return {
        info: {
          title: "Delete Policy Condition",
          data: { ...policyRef, policyConditionId },
        },
        param: { ...policyRef, policyConditionId },
        method: isId
          ? "deletePolicyCondition(uint256,uint256)"
          : "deletePolicyCondition(string,uint256)",
      };
    }
    case "updatePolicy": {
      const [policyIdorName, descriptionInput] = inputs as [
        string,
        string | string[]
      ];
      Joi.assert(policyIdorName, Joi.string());

      const isId = !Number.isNaN(Number(policyIdorName));
      const policyRef = {
        ...(isId && { policyId: policyIdorName }),
        ...(!isId && { policyName: policyIdorName }),
      };
      const opType = AND_OPERATION;
      const description = Array.isArray(descriptionInput)
        ? descriptionInput[0]
        : descriptionInput;

      return {
        info: {
          title: "Insert Policy",
          data: { ...policyRef, opType, description },
        },
        param: { ...policyRef, opType, description },
        method: isId
          ? "updatePolicy(uint256,uint8,string)"
          : "updatePolicy(string,uint8,string)",
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

export default buildParamTpr;
