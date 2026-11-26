# B2 unseal gate

CommonJS, standard Node libraries only. Importing this module performs no I/O.
This preparation used synthetic temporary files only: no actual vault, Q/B1
reports, Docker, policy fitting or test seeds were read.

```js
const {validateBeforeUnseal, resolveCommittedTestRows} = require('./b2-gate');
const receipt = validateBeforeUnseal(spec);
// The caller has already written/pinned the final B2 freeze.
const {assignments, resolvedTestRows, audit} = resolveCommittedTestRows(receipt);
```

`validateBeforeUnseal` never reads vault contents. It checks public metadata,
actual policy/projection/collector bytes and chronological ordering. It returns
an opaque, frozen, single-use receipt. `resolveCommittedTestRows` requires that
exact object, repeats public checks, reads vault bytes once, checks their SHA256
**before JSON decoding**, and validates all25 rows before returning any result.
No function writes the vault or input assignments. Only the five sealed test
fields are filled in a returned clone; existing B1 values remain unchanged.
Receipts cannot be serialized/reconstructed: a new process revalidates first.

## Input contract

`spec` is a plain JSON-compatible object:

| Field | Required value |
| --- | --- |
| `expectedB1IDs` | Exactly71 unique original `b-train-*` / `b-validation-*` IDs |
| `expectedTestIDs` | Exactly25 unique predefined `b-test-*` IDs |
| `assignments` | All96 original rows; no Q/unknown groups |
| `b1Audit.groups` | Exactly71 normalized actual completion records below |
| `projection`, `collector`, `primaryPolicy`, `vault` | `{path, sha256}` with literal file-byte SHA256 |
| `auxiliaryPolicy` | Omitted or `{enabled:false}`; if enabled, `{enabled:true,path,sha256}` |
| `b2Freeze` | Timestamp and hash bindings below |

Normalized completion record:

```js
{
  group_id: 'b-train-example', split: 'train', scope: 'primary',
  completed: true, capture_ended_utc: '2026-01-01T00:00:00.123456789Z'
}
```

The runtime adapter must derive these records from the actual acquisition index,
with VM capture end timestamps. An interrupted/capped/incomplete acquisition
must not be normalized as complete. App failures alone can remain completed
attempts; this gate does not replace the coverage/functional audit. Q/diagnostic,
test, duplicate, missing or unexpected rows fail before any vault content read.
If present, `phase` must be `B1`; `incomplete`, `capped`, `qualification` cannot
be true. Assignment splits must match completion rows.

Policy JSON uses the actual fields:

- `policy_frozen_at` strictly after `last_development_capture_ended_utc` and the
  latest actual B1/supplement capture end;
- `last_development_capture_ended_utc` at least that latest actual capture;
- `freeze_sha256` equal to the final projection file's SHA256;
- `calibration.train.groups` / `calibration.validation.groups` include at least
  all original groups in each split, with extras bounded by declared supplements.

Projection JSON must have `collector_freeze_sha256` equal to the original B1
master artifact SHA256. Its direct `groups` rows must contain every original71
ID/split/source-workload and only explicitly declared supplements. Original
rows use that master SHA by default; a conflicting per-row binding fails.
Source-workload IDs may repeat within one split, never cross splits. Counts
alone cannot substitute for actual IDs and source bindings.

`b2Freeze` requires:

```js
{
  frozen_at: '2026-01-01T00:00:02Z', // strictly after every enabled policy, not future
  primary_policy_sha256: '...', auxiliary_policy_sha256: null,
  projection_sha256: '...', collector_sha256: '...', vault_sha256: '...',
  b1_audit_sha256: sha256Canonical(spec.b1Audit),
  assignments_sha256: sha256Canonical(spec.assignments)
}
```

Use exported `sha256Canonical` for normalized JSON objects (recursive sorted
object keys; array order retained). Artifact hashes always cover literal bytes.
UTC comparisons retain nanoseconds; equality is not “after”. Disabled auxiliary
artifacts are not opened. Explicit enabled auxiliary policy must independently
satisfy source/count/time checks and precede B2 freeze.

## Optional candidate supplement

Default is none. To include the separately declared six postresponse candidate
development groups, provide all of:

- `expectedSupplementIDs`: exactly6 unique IDs outside original/test/Q;
- `supplementAudit.groups`: complete records for all6, train/validation only,
  with `source_workload_id` and scope `primary` or `candidate-development`;
- `supplementCollectors`: `{path,sha256,group_ids:[...]}` descriptors partitioning
  all6 IDs, each verified against actual bytes;
- per-supplement projection row `collector_freeze_sha256` matching its descriptor;
- `b2Freeze.supplement_audit_sha256 = sha256Canonical(spec.supplementAudit)` and
  `supplement_collector_sha256`: sorted unique supplement source hashes.

All71 original rows remain mandatory. Final policy must be frozen after the
latest supplement capture too. No supplement may use a sealed test workload
source. The original B1 master remains the projection's default source.

## Committed vault shape

Verified bytes decode to an object keyed by the exact25 test IDs:

```js
{
  'b-test-example': {
    seed_int: 123, nonce: '<64 lowercase hex>', initial_nonce: '<64 lowercase hex>',
    warmup_nonces: ['<64hex>', '<64hex>', '<64hex>']
  }
}
```

Before unseal, every test assignment must have `seed_int`, `seed_hex`, `nonce`,
`initial_nonce` literally null and `warmup_nonces:[null,null,null]`;
`sealed_seed_ref === source_workload_id`, `sealed_nonce_ref === group_id`.
After authorization, seeds must be positive integers through `2^48−1`; the
helper derives fixed16hex `seed_hex`. Paired rows sharing a source-workload ID
must share the same seed. All test nonces must be unique, including against open
B1 nonces. Extra/missing IDs/fields, range errors or collisions return no result.
Unknown IDs in public assignments are rejected pre-read; unknown keys inside
committed private bytes can only be rejected after authorized hash/decode.

## I/O and ownership

Optional second argument injects `readFileSync`, `realpathSync`, `statSync`,
`nowUTC` (function returning UTC text). Defaults are Node fs and current UTC.
Vault realpath/stat metadata may be inspected before unseal to reject public
policy aliases (same path, symlink or hardlink); **vault bytes are not opened**.
Inputs must remain pinned during validation/resolve. Receipts recheck public
hashes and current time immediately before the private read. This is a pipeline
sequencing/provenance guard; the runtime still owns actual index normalization,
final source/binary freeze and exact policy use during B2 collection/scoring.

`GateError.code` reports the failing condition without printing vault values.
Returned audit includes actual unseal start/end UTC and public hashes. The caller
owns private storage of resolved assignments; the module has no CLI that could
accidentally unseal a real vault.

Run `node --test lab/dpi-g03/b2-gate/index.test.cjs`. All fixtures are generated in
fresh OS temporary directories and removed afterward. Tests spy on private file
reads and cover early rejection,71/25 IDs, source/hash binding, precise ordering,
auxiliary/supplement opt-in, aliases, mutated artifacts, single-use receipts,
commitment-before-decode, seed/nonce consistency and unchanged input bytes.
