import { EdKeypair } from "ucans"

type Header = {
  alg?: any,
  typ?: any,
  ucv?: any
}

type Payload = {
  iss?: any,
  aud?: any,
  nbf?: any,
  exp?: any,
  nnc?: any,
  fct?: any,
  att?: any,
  prf?: any,
}

type Fixture = {
  comment: string,
  token: string,
  assertions: {
    header?: Header,
    payload?: Payload,
    validationErrors?: ValidationError[],
    typeErrors?: TypeError[],
  }
}

type Witness = {
  issuerKp: EdKeypair,
  token: string,
  header?: Header,
  payload?: Payload,
}

type Part =
  | "header"
  | "payload"
  | "signature"

type TypeError =
  | "algWrongType"
  | "typWrongType"
  | "ucvWrongType"
  | "issWrongType"
  | "audWrongType"
  | "nbfWrongType"
  | "expWrongType"
  | "nncWrongType"
  | "fctWrongType"
  | "attWrongType"
  | "prfWrongType"
  | "algMissing"
  | "typMissing"
  | "ucvMissing"
  | "issMissing"
  | "audMissing"
  | "expMissing"
  | "attMissing"
  | "prfMissing"

type ValidationError =
  | "base64Invalid"
  | "headerMissingOrInvalid"
  | "payloadMissingOrInvalid"
  | "signatureMissingOrInvalid"
  | "algInvalidAlgorithm"
  | "typInvalidType"
  | "ucvInvalidVersion"
  | "issInvalidDidKey"
  | "audInvalidDidKey"
  | "expExpired"
  | "nbfNotReady"
  | "expWitnessTimeBoundExceeded"
  | "attInvalidResource"
  | "attInvalidAbility"


export type {
  Header,
  Payload,
  Part,
  TypeError,
  ValidationError,
  Fixture,
  Witness
}
