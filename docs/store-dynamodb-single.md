# DynamoDB single-table store (`store-dynamodb-single`)

`store-dynamodb-single` keeps all of a service's data in **one DynamoDB table that
you provision yourself**. The service never creates, describes or alters the table,
so its runtime credentials need data-plane permissions only.

It is a build-time alternative to `store-dynamodb` (which creates one table per
keyspace). Enable exactly one storage feature per binary.

| | `store-dynamodb` | `store-dynamodb-single` |
|---|---|---|
| Tables | one per keyspace, created at startup | one, provisioned by you |
| Runtime permissions | table management plus data | data only |
| Prefix listing (`did:`, `owner:` …) | full-table `Scan` | partition-scoped `Query` |

## 1. Create the table

The table must have a string partition key `pk` and a string sort key `sk`. Nothing
else is required (other attributes are written by the service).

```bash
aws dynamodb create-table \
  --table-name webvh \
  --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST \
  --deletion-protection-enabled

# Recommended: point-in-time recovery
aws dynamodb update-continuous-backups --table-name webvh \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true
```

CloudFormation:

```yaml
WebvhTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: webvh
    BillingMode: PAY_PER_REQUEST
    DeletionProtectionEnabled: true
    PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true }
    AttributeDefinitions:
      - { AttributeName: pk, AttributeType: S }
      - { AttributeName: sk, AttributeType: S }
    KeySchema:
      - { AttributeName: pk, KeyType: HASH }
      - { AttributeName: sk, KeyType: RANGE }
```

## 2. Permissions

The service needs these actions on the table, and nothing else
(`TransactWriteItems` is authorised by `PutItem` and `DeleteItem`; it has no action
of its own):

```json
{
  "Effect": "Allow",
  "Action": [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
    "dynamodb:DeleteItem",
    "dynamodb:Query"
  ],
  "Resource": "arn:aws:dynamodb:<region>:<account>:table/webvh"
}
```

No `Scan`, `DescribeTable` or `CreateTable`. Credentials come from the standard AWS
provider chain.

### Least privilege when services share a table

The [key namespace](#4-key-namespace) keeps two services' rows from colliding. It is
**not an access boundary**: it is a prefix the service adds itself, so a credential
that is stolen from one service can read and write every row in the table, whatever
that service's namespace is. Only IAM can enforce the boundary.

The simplest safe layout is **one table per trust boundary**. If services must share
a table, give each its own namespace and scope its role to that namespace's partition
keys with `dynamodb:LeadingKeys`:

```json
{
  "Effect": "Allow",
  "Action": [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
    "dynamodb:DeleteItem",
    "dynamodb:Query"
  ],
  "Resource": "arn:aws:dynamodb:<region>:<account>:table/webvh",
  "Condition": {
    "ForAllValues:StringLike": { "dynamodb:LeadingKeys": ["control#*"] }
  }
}
```

Use the value that matches the service's `dynamodb_key_namespace` (`control#*`,
`server#*`, `witness#*` …). The startup probe reads `<namespace>#_probe`, so it stays
inside the allowed prefix.

- A store with **no namespace** uses bare keyspace names (`acl`, `dids` …), which a
  prefix pattern cannot describe. Set a namespace on every service that shares a
  table.
- Setting a namespace on an existing deployment **moves its rows** (the partition key
  changes), so choose it before first use.
- **The daemon** opens two stores. When they share a table its witness store already
  gets the namespace `witness`; set `DAEMON_STORE_DYNAMODB_KEY_NAMESPACE` as well
  (for example `main`) on a new deployment, and allow both prefixes:
  `["main#*", "witness#*"]`. Otherwise give the daemon a table of its own.

## 3. Configure

| `config.toml` (`[store]`) | Environment | Meaning |
|---|---|---|
| `dynamodb_table_name` | `<PREFIX>_STORE_DYNAMODB_TABLE_NAME` | Table name. **Required**; blank is refused. |
| `dynamodb_region` | `<PREFIX>_STORE_DYNAMODB_REGION` | AWS region. Unset uses the environment's. |
| `dynamodb_key_namespace` | `<PREFIX>_STORE_DYNAMODB_KEY_NAMESPACE` | Optional. See [Key namespace](#4-key-namespace). |
| `dynamodb_consistent_reads` | `<PREFIX>_STORE_DYNAMODB_CONSISTENT_READS` | Optional boolean, default `true`. See [Consistent reads](#5-consistent-reads). |

`<PREFIX>` is the binary's own prefix. The daemon uses `DAEMON_STORE` for its main
store and `DAEMON_WITNESS_STORE` for its witness store.

At startup the service reads one reserved key to confirm the table exists and has
the right key schema. A missing table or a wrong key schema stops startup with a
message saying what to fix. Throttling, a timeout or an access error is logged and
startup continues, so a transient failure never stops a working service from
starting.

## 4. Key namespace

A row's partition key is the **keyspace name** (`acl`, `sessions`, `dids` …). All
services use the same keyspace names, so two stores pointed at one table without a
namespace share rows. Set `dynamodb_key_namespace` and the partition key becomes
`<namespace>#<keyspace>`. Unset, it stays the bare keyspace name, exactly as before
the option existed.

- Allowed: ASCII letters, digits, `_`, `-`, `.`; 1 to 32 characters. Anything else
  is refused at startup.
- A keyspace name containing `#` is refused, so `witness#acl` can only mean the
  keyspace `acl` in the namespace `witness`.
- Do not share one table between a control plane and an edge/server, or between
  environments, without distinct namespaces.

### The daemon's witness store

The daemon opens two stores, `store` and `witness_store`, and both use the keyspaces
`acl` and `witnesses`. On one table they would be the same rows, and a revoke made
through the witness would remove the entry from the control plane's ACL.

So when both resolve to the same table (same name, and not provably different
regions) and neither sets a namespace, **the daemon gives the witness store the key
namespace `witness`**. The main store keeps its bare keyspace names, so its existing
rows do not move. The effective namespace is logged at startup. You can set the
witness namespace explicitly with
`DAEMON_WITNESS_STORE_DYNAMODB_KEY_NAMESPACE`. Stores on different tables are left
alone.

If the two stores still resolve to the same partitions (for example both set to the
same namespace) the daemon **refuses to start** and names the variables to change.

**Upgrading a daemon whose stores already share a table.** The main store is
unaffected. The witness store starts from empty `witness#acl` and
`witness#witnesses`: it stops reading (and editing) the control plane's ACL rows, and
any witness data already written under the bare `witnesses` keyspace is no longer
visible to it. Before upgrading a deployment that uses the witness, check whether
that data exists:

```bash
aws dynamodb query --table-name <table> --select COUNT \
  --key-condition-expression "pk = :p" \
  --expression-attribute-values '{":p":{"S":"witnesses"}}'
```

A count of `0` means there is nothing to carry over. The daemon has no command to
seed the witness ACL; until one exists the embedded witness has an empty ACL, as in
every daemon with separate stores.

## 5. Consistent reads

Reads (`GetItem`, `Query`) are **strongly consistent by default**, so a read sees
every write that completed before it. This matters for sessions, refresh tokens,
lockout counters and the outbound queue. Strongly consistent reads use twice the
read capacity of eventually consistent ones. To trade that guarantee for cost, set
`dynamodb_consistent_reads = false`. Writes are unaffected.

## 6. Limits

- **A batch is one transaction.** DynamoDB's `TransactWriteItems` holds at most 100
  operations and 4 MB. A batch larger than that is **refused before anything is
  written** with a validation error, rather than split (a split batch is not atomic).
  Code that writes in bulk chunks to `Store::batch_limits()` itself; the server's
  backup restore and the control plane's stats flush do.
- **A DID may claim at most 47 agent names** (`alsoKnownAs`). Publishing a DID writes
  one name-index row per name and removes the rows of names it drops, and an edge
  syncing it adds the record, log, owner, witness and two high-water rows, all in one
  atomic batch: `2 × 47 + 6 = 100`. The control plane refuses a document over that up
  front with a validation error naming the limit, so nothing is accepted that an edge
  could not then store. A control plane on a store without a batch ceiling (fjall,
  Redis) has no such cap: if its edges run on this backend, keep documents within 47
  names, or an edge will refuse the sync.
- **Deleting a witness identity that has witnessed 100 or more DIDs** cannot be one
  atomic write (the record plus one mark per DID). The identity is removed first, in
  one atomic write that leaves a `deleting:<id>` marker in the `witnesses` keyspace;
  its marks are then removed in batches within the limit, the last also clearing the
  marker. From the first write the identity can sign nothing and is no longer listed.
  If the process stops part-way, the next start finishes the cleanup (the marker is
  what it looks for). A smaller identity is still deleted in one write, as on every
  other backend.
- A batch that touches the same key twice is refused.
- An item is limited by DynamoDB to 400 KB.
- **Keys must be valid UTF-8** (every key the services write is). A key that is not
  is an error, never altered to fit.

## 7. Row format

This is the on-table contract; it does not change without a migration.

| Attribute | Type | Content |
|---|---|---|
| `pk` | String (partition key) | the keyspace name, or `<namespace>#<keyspace>` |
| `sk` | String (sort key) | the key, as UTF-8, unprefixed |
| `val` | Binary | the value bytes |
| `cnt` | Number | an atomic counter; a counter item has no `val` |

A key is either a value or a counter: writing a value replaces the whole item.

## 8. Running the tests

```bash
docker run -d -p 8000:8000 amazon/dynamodb-local

DYNAMODB_SINGLE_TEST_ENDPOINT=http://localhost:8000 \
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \
AWS_ENDPOINT_URL=http://localhost:8000 \
  cargo test -p did-hosting-common --no-default-features \
    --features "server-core,store-dynamodb-single,method-webvh,method-web" \
    --test dynamodb_single_table -- --test-threads=1
```

Without `DYNAMODB_SINGLE_TEST_ENDPOINT` the integration tests skip; if `CI` is set
they fail instead, so a misconfigured pipeline cannot pass having tested nothing.
