# Contributing

Thanks for your interest in improving the checker. Contributions of any size are welcome.

## Getting started

```bash
npm install
npm run build       # tsup -> dist/
npm run typecheck   # tsc --noEmit
npm test            # vitest
npm run smoke       # spawn the built server and exercise every tool live
```

The unit tests in `src/engine.test.ts` mock the network, so they run offline and deterministically. The smoke test in `test/smoke.mjs` makes real lookups and asserts response structure, not exact scores.

## Making a change

1. Fork the repo and create a branch off `main`.
2. Make your change. Keep the engine language-agnostic: it emits i18n keys, and any new user-facing string needs both `es` and `en` entries in `src/i18n.ts` (the key-parity test enforces this).
3. Add or update tests. `npm test` must pass, along with `npm run typecheck` and `npm run build`.
4. Add a changeset describing the change:

   ```bash
   npm run changeset
   ```

   Pick the bump level (patch/minor/major) and write a short summary. The changeset file goes in `.changeset/` and ships with your PR.

## Opening a pull request

- Keep the PR focused on one thing.
- Make sure CI is green: the `verify` job runs typecheck, build, and tests on Node 18, 20, and 22.
- Describe what changed and why. Link any related issue.

## Code style

- TypeScript, ES modules, strict mode.
- Comments in English, only where they earn their place.
- No new runtime dependencies without a good reason.

## Reporting bugs and security issues

Open an issue for ordinary bugs. For anything security-sensitive, follow [SECURITY.md](SECURITY.md) instead of filing a public issue.
