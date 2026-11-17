# did-hosting-ui

The management console for the DID hosting control plane: an Expo Router web
app (React Native Web). It is not deployed on its own. The control plane
embeds the exported bundle and serves it at the root, on the same origin as
its API, so a standalone `did-hosting-control` and a `did-hosting-daemon`
ship the same console.

Every management action the console takes is a signed Trust Task sent to the
control plane's `POST /api/trust-tasks` (`lib/trust-task.ts`). Apart from
that, it calls only `GET /api/health`, `GET /api/sign-in/readiness` and
`POST /api/auth/challenge` (the legacy wallet sign-in).

## Requirements

Node.js at or above `engines.node` in [package.json](package.json). The
control plane's build script reads the same field.

```bash
npm ci
```

## Development

```bash
npm start            # Expo's web dev server (same as `npm run web`)
```

The console sends its API calls to paths on its own origin (`/api/...`), so
the dev server by itself has no control plane behind it. To work against a
real one, export the bundle and run the control plane (below), or put both
behind one origin.

### Environment variables

Expo inlines `EXPO_PUBLIC_*` variables at build time, so set them when you
run `npm start` or `npm run build:web`. All are optional.

| Variable                        | Default                                         | Used for                                                                                                                     |
| ------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `EXPO_PUBLIC_API_BASE`          | `<page origin>/api`                             | The API base the wallet is given for sign-in and step-up (`lib/api-base.ts`). Set it only when the API is on another origin. |
| `EXPO_PUBLIC_RP_DID`            | the control plane's own DID, from `server/info` | The DID the wallet signs the legacy SIOPv2 login for (`lib/wallet.ts`).                                                      |
| `EXPO_PUBLIC_TRIGGER_LINK_HOST` | `link.trustoverip.org`                          | The host of the trigger link for wallet sign-in (`lib/oob-sign-in.ts`).                                                      |

## Building for the control plane

```bash
npm run build:web
```

This exports the web bundle into `../did-hosting-control/ui-dist/`, which the
control plane embeds when its `ui` feature is on (the default). With that
feature on, `did-hosting-control`'s `build.rs` also runs `npm run build:web`
itself (after `npm install` when `node_modules` is missing or older than the
lock file) whenever `ui-dist` is missing or older than the UI sources, so
`cargo build` in the workspace keeps the bundle current.
`ui-dist/` is gitignored. Build it before publishing the crate, as described
in [RELEASES.md](../RELEASES.md).

## Trust Task types

The request and response types under `lib/trust-tasks/` are generated, never
edited by hand. They come from the same lock file the Rust workspace builds
from, `../did-hosting-common/trust-tasks.lock`. After a task is added or moved
there, regenerate them:

```bash
npm run gen:tasks
```

## Checks

CI runs the first four, then a web export:

```bash
npm run typecheck    # tsc --noEmit
npm run lint         # ESLint, warnings fail
npm run format:check # Prettier (npm run format rewrites)
npm test             # Vitest (npm run test:watch to watch)
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the rest of the workspace's
checks.
