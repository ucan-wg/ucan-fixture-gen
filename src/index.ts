import {
  generateInvalidSamplesBase64,
  generateInvalidSamplesMain,
  generateInvalidSamplesMissingParts,
  generateInvalidSamplesTimeBound,
  generateInvalidSamplesAlignment,
  generateInvalidSamplesRedelegation,
  generateValidSampleRedelegation,
  generateValidSampleRightsAmplification,
  generateValidSamplesAlignment,
  generateValidSamplesMain,
  generateValidSamplesTimeBound,
} from "./samples";

async function generateInvalidSamples() {
  generateInvalidSamplesBase64();
  await generateInvalidSamplesMissingParts();
  await generateInvalidSamplesTimeBound();
  await generateInvalidSamplesAlignment();
  await generateInvalidSamplesRedelegation();
  await generateInvalidSamplesMain();
}

async function generateValidSamples() {
  await generateValidSampleRightsAmplification();
  await generateValidSamplesAlignment();
  await generateValidSamplesTimeBound();
  await generateValidSampleRedelegation();
  await generateValidSamplesMain();
}

(async () => {
  if (process.argv.length > 2 && process.argv[2] === "invalid") {
    await generateInvalidSamples();
  } else {
    await generateValidSamples();
  }
})();
