import { blsCreateProof, blsSign, blsVerify, blsVerifyProof, generateBls12381G2KeyPair } from "@mattrglobal/bbs-signatures"
import _ from "lodash"

function toUint8Array(a: any) {
  return Uint8Array.from(Buffer.from(a.toString(), "utf8"))
}

function toBase64String(a: Uint8Array) {
  return Buffer.from(a).toString("base64")
}

function toUtf8String(a: Uint8Array) {
  return Buffer.from(a).toString("utf8")
}

class Transcript {
  name: string
  major: string
  gpa: number

  constructor(name: string, major: string, gpa: number) {
    this.name = name
    this.major = major
    this.gpa = gpa
  }

  toMessage() {
    return [
      toUint8Array(this.name),
      toUint8Array(this.major),
      toUint8Array(this.gpa),
    ]
  }
}

const main = async () => {
  const transcript = new Transcript("yoisha", "Electrical Engineering", 4.00);
  const MIT_KEY = await generateBls12381G2KeyPair()
  const HAVARD_KEY = await generateBls12381G2KeyPair()

  console.log("MIT Public Key", toBase64String(MIT_KEY.publicKey));
  console.log("HAVARD Public Key", toBase64String(HAVARD_KEY.publicKey));

  console.log("MIT signing yoi's transcript");

  //MIT create the signature
  const signature = await blsSign({
    keyPair: MIT_KEY,
    messages: transcript.toMessage(),
  });

  console.log(
    `Output signature base64 ${toBase64String(signature)}`
  );

  //yoisha can derive a proof from the signature revealing his name and major
  const proof = await blsCreateProof({
    signature,
    publicKey: MIT_KEY.publicKey,
    messages: transcript.toMessage(),
    nonce: toUint8Array(0),
    revealed: [0, 1],
  });
  console.log(`Output proof base64 ${toBase64String(signature)}`);

  //other can verify that the created proof has been signed by MIT
  const isProofVerifiedMIT = await blsVerifyProof({
    proof,
    publicKey: MIT_KEY.publicKey,
    messages: [toUint8Array("yoisha"), toUint8Array("Electrical Engineering")],
    nonce: toUint8Array(0),
  });
  console.log(`Proof verified for MIT key? ${isProofVerifiedMIT.verified}`);

  //other can verify that the created proof has been signed by HAVARD
  const isProofVerifiedHAVARD = await blsVerifyProof({
    proof,
    publicKey: HAVARD_KEY.publicKey,
    messages: [toUint8Array("yoisha"), toUint8Array("Electrical Engineering")],
    nonce: toUint8Array(0),
  });
  console.log(`Proof verified for HAVARD key? ${isProofVerifiedHAVARD.verified}`);
}

main()
