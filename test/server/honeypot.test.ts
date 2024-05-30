import CryptoJS from "crypto-js";
import { describe, expect, test } from "vitest";
import { Honeypot, SpamError } from "../../src/server/honeypot";

// biome-ignore lint/suspicious/noExplicitAny: Test
function invariant(condition: any, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

describe(Honeypot.name, () => {
  test("generates input props", () => {
    const props = new Honeypot().getInputProps();
    expect(props).toEqual({
      nameFieldName: "name__confirm",
      validFromFieldName: "from__confirm",
      encryptedValidFrom: expect.any(String),
    });
  });

  test("uses randomized nameFieldName", () => {
    const honeypot = new Honeypot({ randomizeNameFieldName: true });
    const props = honeypot.getInputProps();
    expect(props.nameFieldName.startsWith("name__confirm_")).toBeTruthy();
  });

  test("uses randomized nameFieldName with prefix", () => {
    const honeypot = new Honeypot({
      randomizeNameFieldName: true,
      nameFieldName: "prefix",
    });
    const props = honeypot.getInputProps();
    expect(props.nameFieldName.startsWith("prefix_")).toBeTruthy();
  });

  test("checks validity on FormData", () => {
    const formData = new FormData();
    const result = new Honeypot().check(formData);
    expect(result).toBeUndefined();
  });

  test("checks validity of FormData with encrypted timestamp and randomized field name", () => {
    const honeypot = new Honeypot({ randomizeNameFieldName: true });

    const props = honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(props.validFromFieldName, props.encryptedValidFrom);

    expect(honeypot.check(formData)).toBeUndefined();
  });

  test("fails validity check if input is not present", () => {
    const honeypot = new Honeypot();
    const props = honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.validFromFieldName, props.encryptedValidFrom);

    expect(() => honeypot.check(formData)).toThrowError(
      new SpamError("Missing honeypot input")
    );
  });

  test("fails validity check if input is not empty", () => {
    const honeypot = new Honeypot();
    const props = honeypot.getInputProps();

    const formData = new FormData();
    formData.set(props.nameFieldName, "not empty");

    expect(() => honeypot.check(formData)).toThrowError(
      new SpamError("Honeypot input not empty")
    );
  });

  test("fails if valid from timestamp is missing", () => {
    const honeypot = new Honeypot();
    const props = honeypot.getInputProps();

    const formData = new FormData();
    formData.set(props.nameFieldName, "");

    expect(() => honeypot.check(formData)).toThrowError(
      new SpamError("Missing honeypot valid from input")
    );
  });

  test("fails if the timestamp is not valid", () => {
    const honeypot = new Honeypot({
      encryptionSeed: "SEED",
    });
    const props = honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(
      props.validFromFieldName,
      CryptoJS.AES.encrypt("invalid", "SEED").toString()
    );

    expect(() => honeypot.check(formData)).toThrowError(
      new SpamError("Invalid honeypot valid from input")
    );
  });

  test("fails if valid from timestamp is in the future", () => {
    const honeypot = new Honeypot({
      encryptionSeed: "SEED",
    });

    const props = honeypot.getInputProps();
    invariant(props.validFromFieldName, "validFromFieldName is null");

    const formData = new FormData();
    formData.set(props.nameFieldName, "");
    formData.set(
      props.validFromFieldName,
      CryptoJS.AES.encrypt((Date.now() + 10_000).toString(), "SEED").toString()
    );

    expect(() => honeypot.check(formData)).toThrowError(
      new SpamError("Honeypot valid from is in future")
    );
  });

  test("does not check for valid from timestamp if it's set to null", () => {
    const honeypot = new Honeypot({
      validFromFieldName: null,
    });

    const props = honeypot.getInputProps();
    expect(props.validFromFieldName).toBeNull();

    const formData = new FormData();
    formData.set(props.nameFieldName, "");

    expect(() => honeypot.check(formData)).not.toThrow();
  });
});
