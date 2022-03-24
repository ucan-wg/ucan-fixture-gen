import { generateInvalidSamplesBase64, generateInvalidSamplesMain, generateInvalidSamplesMissingParts, generateInvalidSamplesTimeBound } from './samples';

(async () => {
  generateInvalidSamplesBase64();
  await generateInvalidSamplesMain();
  await generateInvalidSamplesMissingParts();
  await generateInvalidSamplesTimeBound();
})()
