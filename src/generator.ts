import { EdKeypair } from "ucans";
import * as uint8arrays from "uint8arrays";
import moment from "moment";
import {
  Header,
  Payload,
  Part,
  TypeError,
  ValidationError,
  Fixture,
  Witness,
} from "./types";

// Default header.
const defaultHeader: Header = {
  alg: "EdDSA",
  typ: "JWT",
  ucv: "0.8.1",
};

/** Converts a UCAN header or payload to url-safe base64 */
const toBase64String = (obj: Header | Payload): String => {
  const str = JSON.stringify(obj);
  return uint8arrays.toString(uint8arrays.fromString(str, "utf8"), "base64url");
};

/** Signs a string with given keypair */
async function sign(toSign: string, keypair: EdKeypair): Promise<Uint8Array> {
  return keypair.sign(uint8arrays.fromString(toSign, "utf8"));
}

/** Generates an EdDSA key pair */
async function generateEdKeypair(): Promise<EdKeypair> {
  return await EdKeypair.create();
}

/** Generates a spec test fixture */
async function generateSpecFixture(opts: {
  comment: string;
  issuerKp: EdKeypair;
  audience?: string;
  header?: Header;
  payload?: Payload;
  typeErrors?: TypeError[];
  validationErrors?: ValidationError[];
  missingPart?: Part;
  noPrint?: boolean;
}): Promise<Fixture> {
  const defaultPayload: Payload = {
    iss: opts.issuerKp.did(),
    aud: opts.audience,
    nbf: undefined,
    exp: moment().add(100, "years").unix(),
    nnc: undefined,
    fct: undefined,
    att: [],
    prf: [],
  };

  // Factor in user-provided header and payload fields.
  const newHeader: Header = { ...defaultHeader, ...opts.header };
  const newPayload: Payload = { ...defaultPayload, ...opts.payload };

  // Get base64 strings of header and payload.
  const headerBase64 = toBase64String(newHeader);
  const payloadBase64 = toBase64String(newPayload);

  // Sign the joined parts.
  const signature = await sign(
    `${headerBase64}.${payloadBase64}`,
    opts.issuerKp
  );
  const signatureBase64 = uint8arrays.toString(signature, "base64url");

  // Construct the JWT.
  let token: string;
  let assertionHeader: Header | undefined = newHeader;
  let assertionPayload: Payload | undefined = newPayload;

  switch (opts.missingPart) {
    case "header":
      token = `${payloadBase64}.${signatureBase64}`;
      assertionHeader = undefined;
      break;
    case "payload":
      token = `${headerBase64}.${signatureBase64}`;
      assertionPayload = undefined;
      break;
    case "signature":
      token = `${headerBase64}.${payloadBase64}`;
      break;
    default:
      token = `${headerBase64}.${payloadBase64}.${signatureBase64}`;
  }

  // Get the fixture.
  const fixture: Fixture = {
    comment: opts.comment,
    token,
    assertions: {
      header: assertionHeader,
      payload: assertionPayload,
      validationErrors: opts.validationErrors,
      typeErrors: opts.typeErrors,
    },
  };

  if (!opts.noPrint) {
    console.log(JSON.stringify(fixture, null, 2));
  }

  return fixture;
}

/** Generates a witness for a UCAN */
async function generateWitness(opts: {
  audience?: string;
  header?: Header;
  payload?: Payload;
}): Promise<Witness> {
  const issuerKp = await generateEdKeypair();

  const defaultPayload: Payload = {
    iss: issuerKp.did(),
    aud: opts.audience,
    nbf: undefined,
    exp: moment().add(120, "years").unix(),
    nnc: undefined,
    fct: undefined,
    att: [],
    prf: [],
  };

  // Factor in user-provided header and payload fields.
  const newHeader: Header = { ...defaultHeader, ...opts.header };
  const newPayload: Payload = { ...defaultPayload, ...opts.payload };

  const { token } = await generateSpecFixture({
    comment: "",
    issuerKp,
    audience: opts.audience,
    header: newHeader,
    payload: newPayload,
    noPrint: true,
  });

  return {
    issuerKp,
    token,
    header: newHeader,
    payload: newPayload,
  };
}

export { generateEdKeypair, generateSpecFixture, generateWitness };
