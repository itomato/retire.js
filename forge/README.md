# Ebira interior adapter

This directory is maintained by the Ebira fork of Retire.js. It exposes the
Retire.js detection engine as a bounded, side-effect-free API for observations
captured from the interior of an Atlassian Forge app.

The adapter does not crawl tenants, fetch arbitrary URLs, or read another
app's filesystem. Callers provide authorized URI, filename, and JavaScript
content observations. Returned reports include component/version matches,
Retire.js advisories, evidence references, and content hashes; raw content is
not returned.

```js
const { scanInteriorObservations } = require('./interior');

const report = scanInteriorObservations([
  {
    evidenceRef: 'asset:main-js',
    surfaceId: 'module:admin-page',
    fileName: 'jquery-3.4.0.min.js',
    content: '/*! jQuery v3.4.0 */',
  },
]);
```
