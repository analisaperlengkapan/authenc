## What this changes

<!-- What behaviour is different after this, and why. -->

## What it does not change

<!-- Anything you deliberately left out, and anything you could not verify.
     A partial change described accurately is useful; a partial change
     described as complete is not. -->

## Verification

<!-- How you know it works. Name the tests, or the commands you ran. -->

- [ ] `just check` passes (fmt, clippy on both targets, tests, layer boundaries)
- [ ] New behaviour has a test that fails if the implementation is removed
- [ ] `.sqlx/` regenerated and committed, if any SQL changed
- [ ] Docs updated, if behaviour or setup changed

## Security

- [ ] No new route is reachable without authentication that should not be
- [ ] No secret is logged, and no internal error detail reaches a client
- [ ] No verification function returns success without verifying
