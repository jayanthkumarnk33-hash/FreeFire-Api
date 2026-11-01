# Credential rotation plan

Status: **action required by the repository owner**. No secret value appears in
this document.

## What is exposed

**Two** files, holding **two different sets** of live guest-account credentials:

| Path | Entries | Tracked since |
|---|---|---|
| `Configuration/AccountConfiguration.json` | 13 (uid + SHA-256 password hash) | initial commit |
| `AccountConfiguration.json` (repo root) | 13, **different uids** | initial commit `3aea094` |

That is **26 live credential pairs**, not 13. The two files share no uids, so they
are distinct accounts. The root copy is not read by the application
(`Utilities.until.load_accounts` opens `./Configuration/AccountConfiguration.json`
only), so it is a stray duplicate that leaked with no functional purpose.

Every clone, fork and cached commit contains both sets.

## Action taken in this pass

1. Added both paths to `.gitignore`.
2. Removed both from the git index (`git rm --cached`). The working copies are
   preserved, so the API keeps working.
3. Added `Configuration/AccountConfiguration.example.json` with placeholder
   values so a fresh clone knows the expected shape.

Removing the file from the index does **not** purge it from history. That is a
separate, deliberate decision for the owner because it rewrites commits.

## Why rotation is the only real fix

These accounts authenticate successfully at the Garena OAuth layer (HTTP 200 with
an `access_token`), so the credentials are **live**, not stale. Untracking the
file stops future leaks but does not un-leak what is already published.

## Recommended rotation steps

1. Treat all 13 `uid`/`password` pairs as compromised.
2. Decide whether history rewriting is warranted. If yes, use
   `git filter-repo` (not `filter-branch`) on a **private mirror**, then force
   push and ask all collaborators to re-clone. If no, proceed to step 3.
3. Issue replacement credentials for any account that will continue to be used.
   Note: guest self-registration currently returns HTTP 404 `error_not_found`, so
   replacements cannot be minted through the repository's generator. See
   `registration-404-analysis.md`.
4. Put the new values in the **local, untracked**
   `Configuration/AccountConfiguration.json` only, and delete the root-level
   `AccountConfiguration.json` so a second copy cannot reappear.
5. Confirm `git status` lists neither file, and that
   `git check-ignore -v Configuration/AccountConfiguration.json AccountConfiguration.json`
   reports both as ignored.
6. If any credential is ever committed again, rotate it rather than relying on a
   later deletion.

## Safer handling going forward

- Prefer environment variables or a secret manager over a JSON file. A small
  change to `Utilities.until.load_accounts()` could read
  `FF_ACCOUNT_CONFIG` as a path or a JSON string, falling back to the file.
- The file is read-only data; no code writes to it except the generator, which
  now refuses to overwrite without `--force` and defaults to a separate output
  path.

## What was NOT done, and why

No credential was printed, echoed, committed or transmitted during this work. The
values were only ever read into memory to make the authenticated requests the
task required.
