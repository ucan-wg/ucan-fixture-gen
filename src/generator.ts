import { EdKeypair } from 'ucans'
import * as uint8arrays from 'uint8arrays'
import moment from 'moment'
import { Header, Payload, Part, TypeError, ValidationError, Fixture, Witness } from './types'

const defaultHeader: Header = {
  alg: "EdDSA",
  typ: "JWT",
  ucv: "0.8",
}

const toBase64String = (obj: Header | Payload): String => {
  const str = JSON.stringify(obj)
  return uint8arrays.toString(uint8arrays.fromString(str, "utf8"), "base64url")
}

export const sign = async (toSign: string, keypair: EdKeypair): Promise<Uint8Array> => {
  return keypair.sign(uint8arrays.fromString(toSign, "utf8"))
}

export const generateEdKeypair = async (): Promise<EdKeypair> => {
  return await EdKeypair.create()
}

// TODO: Overload function.
export const generateSpecFixture = async (
  comment: string,
  issuerKp: EdKeypair,
  audience?: string,
  header?: Header,
  payload?: Payload,
  typeErrors?: TypeError[],
  validationErrors?: ValidationError[],
  missingPart?: Part,
  noPrint: boolean = false
): Promise<Fixture> => {
  const defaultPayload: Payload = {
    iss: issuerKp.did(),
    aud: audience,
    nbf: undefined,
    exp: moment().unix(),
    nnc: undefined,
    fct: undefined,
    att: [],
    prf: []
  }

  // Factor in user-provided header and payload fields.
  const newHeader: Header = { ...defaultHeader, ...header }
  const newPayload: Payload = { ...defaultPayload, ...payload }

  // Get base64 strings of header and payload.
  const headerBase64 = toBase64String(newHeader)
  const payloadBase64 = toBase64String(newPayload)

  // Sign the joined parts.
  const signature = await sign(`${headerBase64}.${payloadBase64}`, issuerKp)
  const signatureBase64 = uint8arrays.toString(signature, "base64url")

  // Construct the JWT.
  let token: string
  let assertionHeader: Header | undefined = newHeader
  let assertionPayload: Payload | undefined = newPayload

  switch (missingPart) {
    case "header":
      token = `${payloadBase64}.${signatureBase64}`
      assertionHeader = undefined
      break
    case "payload":
      token = `${headerBase64}.${signatureBase64}`
      assertionPayload = undefined
      break
    case "signature":
      token = `${headerBase64}.${payloadBase64}`
      break
    default:
      token = `${headerBase64}.${payloadBase64}.${signatureBase64}`
  }

  // Get the fixture.
  const fixture: Fixture = {
    comment,
    token,
    assertions: {
      header: assertionHeader,
      payload: assertionPayload,
      validationErrors,
      typeErrors,
    }
  }

  if (!noPrint) {
    console.log(JSON.stringify(fixture, null, 2))
  }

  return fixture
}

export const generateWitness = async (audience?: string, header?: Header, payload?: Payload): Promise<Witness> => {
  const issuerKp = await generateEdKeypair()

  const defaultPayload: Payload = {
    iss: issuerKp.did(),
    aud: audience,
    nbf: undefined,
    exp: moment().unix(),
    nnc: undefined,
    fct: undefined,
    att: [],
    prf: []
  }

  // Factor in user-provided header and payload fields.
  const newHeader: Header = { ...defaultHeader, ...header }
  const newPayload: Payload = { ...defaultPayload, ...payload }

  const { token } = await generateSpecFixture("", issuerKp, audience, newHeader, newPayload, undefined, undefined, undefined, true)

  return {
    issuerKp,
    token,
    header: newHeader,
    payload: newPayload,
  }
}
