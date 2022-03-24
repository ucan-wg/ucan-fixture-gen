import { generateEdKeypair, generateSpecFixture, generateWitness } from './generator'
import { EdKeypair } from 'ucans'
import moment from 'moment';
import { Fixture } from './types';

let issuerKp: EdKeypair
let audience: string

const setKeypairs = async (): Promise<{ issuerKp: EdKeypair, audience: string }> => {
  if (!(issuerKp && audience)) {
    issuerKp = await generateEdKeypair()
    audience = (await generateEdKeypair()).did()
  }

  return { issuerKp, audience }
}

export const generateInvalidSamplesBase64 = () => {
  const fixture: Fixture = {
    comment: "UCAN sections contain invalid base64 characters",
    token: "@@JhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuOCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtySnpWZVk3RXd2cVdNc3ROeDJ4SDdiZGVnYWREZGFjOHVGams2NTlnemJkeCIsImF1ZCI6ImRpZDprZXk6ek0wMG04RHhXU3dRaGhaWWJnUGprQ05qbUx2dmEzRDdxQnNHUHZ3ejJneW5TaWFKIiwiZXhwIjoxNjQ4MDc2MDQ0LCJhdHQiOltdLCJwcmYiOltdfQ.vLgf-O3Xrc94toabVJKoI15EmAO-d9SqHGFbxTkw3wyEZb-Q7YXA-6mWJv6b-b7kFQHiilMcdIl5s5IuXxsSAw",
    assertions: {
      validationErrors: ["base64Invalid"]
    }
  }

  console.log(JSON.stringify(fixture, null, 2))
}

export const generateInvalidSamplesMissingParts = async () => {
  const { issuerKp, audience } = await setKeypairs()

  await generateSpecFixture("UCAN header section is missing or invalid", issuerKp, audience, undefined, undefined, undefined, ["headerMissingOrInvalid"], "header")

  await generateSpecFixture("UCAN payload section is missing or invalid", issuerKp, audience, undefined, undefined, undefined, ["payloadMissingOrInvalid"], "payload")

  await generateSpecFixture("UCAN signature is missing or invalid", issuerKp, audience, undefined, undefined, undefined, ["signatureMissingOrInvalid"], "signature")
}

export const generateInvalidSamplesMain = async () => {
  const { issuerKp, audience } = await setKeypairs()

  await generateSpecFixture("Header `alg` field should be a string", issuerKp, audience, { alg: 1 }, undefined, ["algWrongType"])

  await generateSpecFixture("Header is missing an `alg` field", issuerKp, audience, { alg: undefined }, undefined, ["algMissing"])

  await generateSpecFixture("UCAN algorithm is not valid", issuerKp, audience, { alg: "" }, undefined, undefined, ["algInvalidAlgorithm"])

  await generateSpecFixture("Header `typ` field should be a string", issuerKp, audience, { typ: 1 }, undefined, ["typWrongType"])

  await generateSpecFixture("Header is missing a `typ` field", issuerKp, audience, { typ: undefined }, undefined, ["typMissing"])

  await generateSpecFixture("UCAN type is not valid", issuerKp, audience, { typ: "" }, undefined, undefined, ["typInvalidType"])

  await generateSpecFixture("Header `ucv` field should be a string", issuerKp, audience, { ucv: 1 }, undefined, ["ucvWrongType"])

  await generateSpecFixture("Header is missing a `ucv` field", issuerKp, audience, { ucv: undefined }, undefined, ["ucvMissing"])

  await generateSpecFixture("UCAN version is not valid", issuerKp, audience, { ucv: "0.7" }, undefined, undefined, ["ucvInvalidVersion"])

  await generateSpecFixture("Payload `iss` field should be a did:key string", issuerKp, audience, undefined, { iss: 1 }, ["issWrongType"])

  await generateSpecFixture("Payload is missing an `iss` field", issuerKp, audience, undefined, { iss: undefined }, ["issMissing"])

  await generateSpecFixture("UCAN issuer did:key is not valid", issuerKp, audience, undefined, { iss: "" }, undefined, ["issInvalidDidKey"])

  await generateSpecFixture("UCAN issuer did:key is not valid", issuerKp, audience, undefined, { iss: "did:key:zM++m8DxWSwQhhZYbgPjkCNjmLvva3D7qBsGPvwz2gynSiaJ" }, undefined, ["issInvalidDidKey"])

  await generateSpecFixture("Payload `aud` field should be a did:key string", issuerKp, audience, undefined, { aud: 1 }, ["audWrongType"])

  await generateSpecFixture("Payload is missing an `aud` field", issuerKp, audience, undefined, { aud: undefined }, ["audMissing"])

  await generateSpecFixture("UCAN audience did:key is not valid", issuerKp, audience, undefined, { aud: "did:key:zM++m8DxWSwQhhZYbgPjkCNjmLvva3D7qBsGPvwz2gynSiaJ" }, undefined, ["audInvalidDidKey"])

  await generateSpecFixture("Payload `nbf` field should be a number", issuerKp, audience, undefined, { nbf: "string" }, ["nbfWrongType"])

  await generateSpecFixture("UCAN audience did:key is not valid", issuerKp, audience, undefined, { aud: "" }, undefined, ["audInvalidDidKey"])

  await generateSpecFixture("UCAN audience did:key is not valid", issuerKp, audience, undefined, { aud: "did:key:zM++m8DxWSwQhhZYbgPjkCNjmLvva3D7qBsGPvwz2gynSiaJ" }, undefined, ["audInvalidDidKey"])

  await generateSpecFixture("Payload `nbf` field should be a number", issuerKp, audience, undefined, { nbf: "string" }, ["nbfWrongType"])

  await generateSpecFixture("Payload `exp` field should be a did:key string", issuerKp, audience, undefined, { exp: "string" }, ["expWrongType"])

  await generateSpecFixture("Payload is missing an `exp` field", issuerKp, audience, undefined, { exp: undefined }, ["expMissing"])

  await generateSpecFixture("Payload `ncc` field should be a string", issuerKp, audience, undefined, { nnc: 1 }, ["nncWrongType"])

  await generateSpecFixture("Payload `fct` field should be an array of json", issuerKp, audience, undefined, { fct: 1 }, ["fctWrongType"])

  await generateSpecFixture("Payload `prf` field should be an array of string", issuerKp, audience, undefined, { prf: 1 }, ["prfWrongType"])

  await generateSpecFixture("Payload `prf` field should be an array of string", issuerKp, audience, undefined, { prf: [1] }, ["prfWrongType"])

  await generateSpecFixture("Payload is missing an `prf` field", issuerKp, audience, undefined, { prf: undefined }, ["prfMissing"])

  await generateSpecFixture("Payload `att` field should be an array of json", issuerKp, audience, undefined, { att: 1 }, ["attWrongType"])

  await generateSpecFixture("Payload is missing an `att` field", issuerKp, audience, undefined, { att: undefined }, ["attMissing"])

  await generateSpecFixture("Payload is missing an `att` field", issuerKp, audience, undefined, { att: undefined }, ["attMissing"])

  await generateSpecFixture("Attenuation resource is not a URI", issuerKp, audience, undefined, {
    att: [
      {
        with: "tamedun.fission.name/public/photos/",
        can: "wnfs/APPEND"
      }
    ]
  }, undefined, ["attInvalidResource"])

  await generateSpecFixture("Attenuation ability is not namespaced", issuerKp, audience, undefined, {
    att: [
      {
        with: "wnfs://tamedun.fission.name/public/photos/",
        can: "APPEND"
      }
    ]
  }, undefined, ["attInvalidAbility"])
}

export const generateInvalidSamplesTimeBound = async () => {
  const { issuerKp, audience } = await setKeypairs()

  await generateSpecFixture("UCAN has expired", issuerKp, audience, undefined, { exp: moment().subtract(5, 'days').unix() }, undefined, ["expExpired"])

  await generateSpecFixture("UCAN is not ready to be used", issuerKp, audience, undefined, {
    nbf: moment().add(100, 'years').unix(),
    exp: moment().add(101, 'years').unix()
  }, undefined, ["nbfNotReady"])

  {
    const witness = await generateWitness(issuerKp.did())

    await generateSpecFixture("Witnesses expire before the delegated", issuerKp, audience, undefined, {
      exp: moment().add(120, 'years').unix(),
      prf: [witness.token]
    }, undefined, ["expWitnessTimeBoundExceeded"])
  }

  {
    const exp = moment().add(120, 'years').unix()

    const witness = await generateWitness(issuerKp.did(), undefined, {
      nbf: moment().add(100, 'years').unix(),
      exp,
    })

    await generateSpecFixture("Witnesses are not ready to be used before the delegated", issuerKp, audience, undefined, {
      nbf: moment().unix(),
      exp,
      prf: [witness.token]
    }, undefined, ["expWitnessTimeBoundExceeded"])
  }
}

export const generateInvalidSamplesAlignment = async () => {
  const { issuerKp, audience } = await setKeypairs()

  {
    const exp = moment().add(100, 'years').unix()

    const witness = await generateWitness("did:key:z6MkmCWh5hAYms5fnU1ShBHBNaU3M1BeoyYgqrQpfhony4Pg", undefined, { exp: moment().add(100, 'years').unix() });

    await generateSpecFixture("Witnesses expire before the delegated", issuerKp, audience, undefined, { exp, prf: [witness.token] }, undefined, ["expWitnessTimeBoundExceeded"])
  }

  // {
  //   const exp = moment().add(100, 'years').unix()

  //   const witness = await generateWitness(issuerKp.did(), {}, { exp })

  //   await generateSpecFixture("Witnesses expire before the delegated", issuerKp, audience, undefined, { exp, prf: [witness.token] }, undefined, ["expWitnessTimeBoundExceeded"])
  // }
}


export const generateValidSamplesMain = async () => {
  const { issuerKp, audience } = await setKeypairs()

  // TODO: add more valid samples
}

export const generateValidSamplesTimeBound = async () => {
  const { issuerKp, audience } = await setKeypairs()

  // TODO: add more valid samples
}
