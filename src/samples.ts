import {
  generateEdKeypair,
  generateSpecFixture,
  generateWitness,
} from "./generator";
import { EdKeypair, validate } from "ucans";
import moment from "moment";
import { Fixture } from "./types";

let issuerKp: EdKeypair;
let audience: string;

const setKeypairs = async (): Promise<{
  issuerKp: EdKeypair;
  audience: string;
}> => {
  if (!(issuerKp && audience)) {
    issuerKp = await generateEdKeypair();
    audience = (await generateEdKeypair()).did();
  }

  return { issuerKp, audience };
};

const generateInvalidSamplesBase64 = () => {
  const fixture: Fixture = {
    comment: "UCAN sections contain invalid base64 characters",
    token:
      "@@JhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuOCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtySnpWZVk3RXd2cVdNc3ROeDJ4SDdiZGVnYWREZGFjOHVGams2NTlnemJkeCIsImF1ZCI6ImRpZDprZXk6ek0wMG04RHhXU3dRaGhaWWJnUGprQ05qbUx2dmEzRDdxQnNHUHZ3ejJneW5TaWFKIiwiZXhwIjoxNjQ4MDc2MDQ0LCJhdHQiOltdLCJwcmYiOltdfQ.vLgf-O3Xrc94toabVJKoI15EmAO-d9SqHGFbxTkw3wyEZb-Q7YXA-6mWJv6b-b7kFQHiilMcdIl5s5IuXxsSAw",
    assertions: {
      validationErrors: ["base64Invalid"],
    },
  };

  console.log(JSON.stringify(fixture, null, 2));
};

const generateInvalidSamplesMissingParts = async () => {
  const { issuerKp, audience } = await setKeypairs();

  await generateSpecFixture({
    comment: "UCAN header section is missing or invalid",
    issuerKp,
    audience,
    validationErrors: ["headerMissingOrInvalid"],
    missingPart: "header",
  });

  await generateSpecFixture({
    comment: "UCAN payload section is missing or invalid",
    issuerKp,
    audience,
    validationErrors: ["payloadMissingOrInvalid"],
    missingPart: "payload",
  });

  await generateSpecFixture({
    comment: "UCAN signature is missing or invalid",
    issuerKp,
    audience,
    validationErrors: ["signatureMissingOrInvalid"],
    missingPart: "signature",
  });
};

const generateInvalidSamplesMain = async () => {
  const { issuerKp, audience } = await setKeypairs();

  await generateSpecFixture({
    comment: "Header `alg` field should be a string",
    issuerKp,
    audience,
    header: { alg: 1 },
    typeErrors: ["algWrongType"],
  });

  await generateSpecFixture({
    comment: "Header is missing an `alg` field",
    issuerKp,
    audience,
    header: { alg: undefined },
    typeErrors: ["algMissing"],
  });

  await generateSpecFixture({
    comment: "UCAN algorithm is not valid",
    issuerKp,
    audience,
    header: { alg: "" },
    validationErrors: ["algInvalidAlgorithm"],
  });

  await generateSpecFixture({
    comment: "Header `typ` field should be a string",
    issuerKp,
    audience,
    header: { typ: 1 },
    typeErrors: ["typWrongType"],
  });

  await generateSpecFixture({
    comment: "Header is missing a `typ` field",
    issuerKp,
    audience,
    header: { typ: undefined },
    typeErrors: ["typMissing"],
  });

  await generateSpecFixture({
    comment: "UCAN type is not valid",
    issuerKp,
    audience,
    header: { typ: "" },
    validationErrors: ["typInvalidType"],
  });

  await generateSpecFixture({
    comment: "Header `ucv` field should be a string",
    issuerKp,
    audience,
    header: { ucv: 1 },
    typeErrors: ["ucvWrongType"],
  });

  await generateSpecFixture({
    comment: "Header is missing a `ucv` field",
    issuerKp,
    audience,
    header: { ucv: undefined },
    typeErrors: ["ucvMissing"],
  });

  await generateSpecFixture({
    comment: "UCAN version is not valid",
    issuerKp,
    audience,
    header: { ucv: "0.7" },
    validationErrors: ["ucvInvalidVersion"],
  });

  await generateSpecFixture({
    comment: "Payload `iss` field should be a did:key string",
    issuerKp,
    audience,
    payload: { iss: 1 },
    typeErrors: ["issWrongType"],
  });

  await generateSpecFixture({
    comment: "Payload is missing an `iss` field",
    issuerKp,
    audience,
    payload: { iss: undefined },
    typeErrors: ["issMissing"],
  });

  await generateSpecFixture({
    comment: "UCAN issuer did:key is not valid",
    issuerKp,
    audience,
    payload: { iss: "" },
    validationErrors: ["issInvalidDidKey"],
  });

  await generateSpecFixture({
    comment: "UCAN issuer did:key is not valid",
    issuerKp,
    audience,
    payload: {
      iss: "did:key:zM++m8DxWSwQhhZYbgPjkCNjmLvva3D7qBsGPvwz2gynSiaJ",
    },
    validationErrors: ["issInvalidDidKey"],
  });

  await generateSpecFixture({
    comment: "Payload `aud` field should be a did:key string",
    issuerKp,
    audience,
    payload: { aud: 1 },
    typeErrors: ["audWrongType"],
  });

  await generateSpecFixture({
    comment: "Payload is missing an `aud` field",
    issuerKp,
    audience,
    payload: { aud: undefined },
    typeErrors: ["audMissing"],
  });

  await generateSpecFixture({
    comment: "UCAN audience did:key is not valid",
    issuerKp,
    audience,
    payload: {
      aud: "did:key:zM++m8DxWSwQhhZYbgPjkCNjmLvva3D7qBsGPvwz2gynSiaJ",
    },
    validationErrors: ["audInvalidDidKey"],
  });

  await generateSpecFixture({
    comment: "Payload `nbf` field should be a number",
    issuerKp,
    audience,
    payload: { nbf: "string" },
    typeErrors: ["nbfWrongType"],
  });

  await generateSpecFixture({
    comment: "UCAN audience did:key is not valid",
    issuerKp,
    audience,
    payload: { aud: "" },
    validationErrors: ["audInvalidDidKey"],
  });

  await generateSpecFixture({
    comment: "UCAN audience did:key is not valid",
    issuerKp,
    audience,
    payload: {
      aud: "did:key:zM++m8DxWSwQhhZYbgPjkCNjmLvva3D7qBsGPvwz2gynSiaJ",
    },
    validationErrors: ["audInvalidDidKey"],
  });

  await generateSpecFixture({
    comment: "Payload `nbf` field should be a number",
    issuerKp,
    audience,
    payload: { nbf: "string" },
    typeErrors: ["nbfWrongType"],
  });

  await generateSpecFixture({
    comment: "Payload `exp` field should be a did:key string",
    issuerKp,
    audience,
    payload: { exp: "string" },
    typeErrors: ["expWrongType"],
  });

  await generateSpecFixture({
    comment: "Payload is missing an `exp` field",
    issuerKp,
    audience,
    payload: { exp: undefined },
    typeErrors: ["expMissing"],
  });

  await generateSpecFixture({
    comment: "Payload `ncc` field should be a string",
    issuerKp,
    audience,
    payload: { nnc: 1 },
    typeErrors: ["nncWrongType"],
  });

  await generateSpecFixture({
    comment: "Payload `fct` field should be an array of json",
    issuerKp,
    audience,
    payload: { fct: 1 },
    typeErrors: ["fctWrongType"],
  });

  await generateSpecFixture({
    comment: "Payload `prf` field should be an array of string",
    issuerKp,
    audience,
    payload: { prf: 1 },
    typeErrors: ["prfWrongType"],
  });

  await generateSpecFixture({
    comment: "Payload `prf` field should be an array of string",
    issuerKp,
    audience,
    payload: { prf: [1] },
    typeErrors: ["prfWrongType"],
  });

  await generateSpecFixture({
    comment: "Payload is missing an `prf` field",
    issuerKp,
    audience,
    payload: { prf: undefined },
    typeErrors: ["prfMissing"],
  });

  await generateSpecFixture({
    comment: "Payload `att` field should be an array of json",
    issuerKp,
    audience,
    payload: { att: 1 },
    typeErrors: ["attWrongType"],
  });

  await generateSpecFixture({
    comment: "Payload is missing an `att` field",
    issuerKp,
    audience,
    payload: { att: undefined },
    typeErrors: ["attMissing"],
  });

  await generateSpecFixture({
    comment: "Attenuation resource is not a URI",
    issuerKp,
    audience,
    payload: {
      att: [
        {
          with: "tamedun.fission.name/public/photos/",
          can: "wnfs/APPEND",
        },
      ],
    },
    validationErrors: ["attInvalidResource"],
  });

  await generateSpecFixture({
    comment: "Attenuation ability is not namespaced",
    issuerKp,
    audience,
    payload: {
      att: [
        {
          with: "wnfs://tamedun.fission.name/public/photos/",
          can: "APPEND",
        },
      ],
    },
    validationErrors: ["attInvalidAbility"],
  });
};

const generateInvalidSamplesTimeBound = async () => {
  const { issuerKp, audience } = await setKeypairs();

  await generateSpecFixture({
    comment: "UCAN has expired",
    issuerKp,
    audience,
    payload: { exp: moment().subtract(5, "days").unix() },
    validationErrors: ["expExpired"],
  });

  await generateSpecFixture({
    comment: "UCAN is not ready to be used",
    issuerKp,
    audience,
    payload: {
      nbf: moment().add(100, "years").unix(),
      exp: moment().add(101, "years").unix(),
    },
    validationErrors: ["nbfNotReady"],
  });

  {
    const witness = await generateWitness({ audience: issuerKp.did() });

    await generateSpecFixture({
      comment: "Witnesses expire before the delegated",
      issuerKp,
      audience,
      payload: {
        exp: moment().add(120, "years").unix(),
        prf: [witness.token],
      },
      validationErrors: ["expWitnessTimeBoundExceeded"],
    });
  }

  {
    const exp = moment().add(120, "years").unix();

    const witness = await generateWitness({
      audience: issuerKp.did(),
      payload: {
        nbf: moment().add(100, "years").unix(),
        exp,
      },
    });

    await generateSpecFixture({
      comment: "Witnesses are not ready to be used before the delegated",
      issuerKp,
      audience,
      payload: {
        nbf: moment().unix(),
        exp,
        prf: [witness.token],
      },
      validationErrors: ["expWitnessTimeBoundExceeded"],
    });
  }
};

const generateInvalidSamplesAlignment = async () => {
  const { issuerKp, audience } = await setKeypairs();

  {
    const exp = moment().add(100, "years").unix();

    const witness = await generateWitness({
      audience: "did:key:z6MkmCWh5hAYms5fnU1ShBHBNaU3M1BeoyYgqrQpfhony4Pg",
      payload: { exp },
    });

    await generateSpecFixture({
      comment:
        "Witness issuer audience did does not align with delegated issuer did",
      issuerKp,
      audience,
      payload: { exp, prf: [witness.token] },
      validationErrors: ["prfWitnessNotAligned"],
    });
  }

  {
    const exp = moment().add(100, "years").unix();

    const witness = await generateWitness({
      audience: issuerKp.did(),
      header: { ucv: "0.7" },
      payload: { exp },
    });

    await generateSpecFixture({
      comment: "Witness UCAN version does not match delegated UCAN version",
      issuerKp,
      audience,
      payload: { exp, prf: [witness.token] },
      validationErrors: ["prfWitnessVersionMismatch"],
    });
  }
};

const generateInvalidSamplesDelegation = async () => {
  const { issuerKp, audience } = await setKeypairs();

  {
    const exp = moment().add(100, "years").unix();

    const witness = await generateWitness({
      audience: issuerKp.did(),
      payload: { exp },
    });

    await generateSpecFixture({
      comment: "Capability has not been delegated",
      issuerKp,
      audience,
      payload: {
        exp,
        prf: [witness.token],
        att: {
          with: "prf/0",
          can: "ucan/DELEGATE",
        },
      },
      validationErrors: ["prfWitnessNotAligned"],
    });
  }
};

const generateValidSamplesMain = async () => {
  const { issuerKp, audience } = await setKeypairs();

  // TODO: add more valid samples
};

const generateValidSamplesTimeBound = async () => {
  const { issuerKp, audience } = await setKeypairs();

  // TODO: add more valid samples
};

export {
  generateInvalidSamplesBase64,
  generateInvalidSamplesMain,
  generateInvalidSamplesTimeBound,
  generateInvalidSamplesAlignment,
  generateInvalidSamplesDelegation,
  generateValidSamplesMain,
  generateValidSamplesTimeBound,
};
