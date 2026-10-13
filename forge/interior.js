/*
 * Ebira integration for Retire.js.
 *
 * This file was added by the Ebira fork. It adapts Retire.js' pure detection
 * functions to observations captured from the interior of an Atlassian Forge
 * app. It deliberately performs no network or filesystem discovery: callers
 * supply evidence gathered through an authorized channel.
 */

const crypto = require('node:crypto');
const retire = require('../node/lib/retire.js');
const repositoryTemplate = require('../repository/jsrepository-v6.json');
const bundledRepository = JSON.parse(retire.replaceVersion(JSON.stringify(repositoryTemplate)));

const DEFAULT_MAX_OBSERVATIONS = 50;
const DEFAULT_MAX_CONTENT_BYTES = 512 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 2 * 1024 * 1024;

function sha1(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

function normalizeObservation(observation, index) {
  if (!observation || typeof observation !== 'object' || Array.isArray(observation)) {
    throw new TypeError(`observations[${index}] must be an object`);
  }
  const evidenceRef = observation.evidenceRef || `observation:${index + 1}`;
  const uri = typeof observation.uri === 'string' ? observation.uri : null;
  const fileName = typeof observation.fileName === 'string' ? observation.fileName : null;
  const content = typeof observation.content === 'string' ? observation.content : null;
  if (!uri && !fileName && content === null) {
    throw new TypeError(`observations[${index}] must include uri, fileName, or content`);
  }
  return {
    evidenceRef,
    surfaceId: observation.surfaceId || null,
    uri,
    fileName,
    content,
  };
}

function mergeComponent(components, detected, observation, method) {
  const key = `${detected.component}@${detected.version}`;
  const current = components.get(key) || {
    component: detected.component,
    version: detected.version,
    npmname: detected.npmname || null,
    basePurl: detected.basePurl || null,
    detections: [],
    vulnerabilities: detected.vulnerabilities || [],
    evidence: [],
  };
  if (!current.detections.includes(method)) current.detections.push(method);
  if (!current.evidence.some((item) => item.evidenceRef === observation.evidenceRef && item.method === method)) {
    current.evidence.push({
      evidenceRef: observation.evidenceRef,
      surfaceId: observation.surfaceId,
      method,
    });
  }
  components.set(key, current);
}

function scanInteriorObservations(observations, options = {}) {
  if (!Array.isArray(observations)) throw new TypeError('observations must be an array');
  const maxObservations = options.maxObservations || DEFAULT_MAX_OBSERVATIONS;
  const maxContentBytes = options.maxContentBytes || DEFAULT_MAX_CONTENT_BYTES;
  const maxTotalBytes = options.maxTotalBytes || DEFAULT_MAX_TOTAL_BYTES;
  if (observations.length > maxObservations) {
    throw new RangeError(`observations exceeds the limit of ${maxObservations}`);
  }

  const repository = options.repository || bundledRepository;
  const components = new Map();
  const evidence = [];
  let totalBytes = 0;

  observations.map(normalizeObservation).forEach((observation) => {
    const contentBytes = observation.content === null ? 0 : Buffer.byteLength(observation.content, 'utf8');
    if (contentBytes > maxContentBytes) {
      throw new RangeError(`${observation.evidenceRef} exceeds the per-observation content limit`);
    }
    totalBytes += contentBytes;
    if (totalBytes > maxTotalBytes) throw new RangeError('observations exceed the total content limit');

    const methods = [];
    if (observation.uri) {
      methods.push(['uri', retire.scanUri(observation.uri, repository)]);
    }
    if (observation.fileName) {
      methods.push(['filename', retire.scanFileName(observation.fileName, repository, true)]);
    }
    if (observation.content !== null) {
      methods.push(['filecontent', retire.scanFileContent(observation.content, repository, { sha1 })]);
    }
    methods.forEach(([method, detections]) => {
      detections.forEach((detected) => mergeComponent(components, detected, observation, method));
    });
    evidence.push({
      evidenceRef: observation.evidenceRef,
      surfaceId: observation.surfaceId,
      signals: methods.map(([method]) => method),
      contentBytes,
      contentSha1: observation.content === null ? null : sha1(observation.content),
    });
  });

  const detected = [...components.values()].sort((left, right) =>
    left.component.localeCompare(right.component) || left.version.localeCompare(right.version),
  );
  return {
    engine: { name: 'retire.js', version: retire.version, repository: 'jsrepository-v6' },
    summary: {
      observationCount: evidence.length,
      componentCount: detected.length,
      vulnerableComponentCount: detected.filter((item) => item.vulnerabilities.length > 0).length,
    },
    components: detected,
    evidence,
  };
}

module.exports = {
  DEFAULT_MAX_CONTENT_BYTES,
  DEFAULT_MAX_OBSERVATIONS,
  DEFAULT_MAX_TOTAL_BYTES,
  scanInteriorObservations,
};
