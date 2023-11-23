export {};
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeJsonString(): R;
      toBeJwt(): R;
    }
  }
}
