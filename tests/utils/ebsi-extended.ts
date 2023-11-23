const ebsiExtended = {
  toBeJsonString(received: string): { pass: boolean; message: () => string } {
    try {
      JSON.parse(received);
      return {
        pass: true,
        message: () => `JSON can be parsed. Received:\n${received}`,
      };
    } catch (error) {
      return {
        pass: false,
        message: () => `JSON can not be parsed. Received:\n${received}`,
      };
    }
  },

  toBeJwt(received: string): { pass: boolean; message: () => string } {
    if (typeof received !== "string")
      return {
        pass: false,
        // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
        message: () => `Not a JWT. Received: ${received}`,
      };
    const parts = received.split(".");
    if (parts.length !== 3)
      return {
        pass: false,
        message: () => `Not a JWT. Received: ${received}`,
      };
    return {
      pass: true,
      message: () => `It is a JWT. Received: ${received}`,
    };
  },
};

export default ebsiExtended;
