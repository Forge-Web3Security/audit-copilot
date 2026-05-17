# Title

## Summary

One or two sentences explaining the broken invariant and affected value flow.

## Vulnerability Detail

Describe the exact root cause. Keep code snippets short.

## Impact

Explain the material loss, frozen funds, unfair mint/redeem, accounting corruption, or protocol insolvency.

## Proof of Concept

Foundry test path:

```bash
forge test --match-test test_<NAME> -vvv
```

## Code Snippet

Link or snippet.

## Tool Used

Manual review, Foundry, Slither/Aderyn as signal sources.

## Recommendation

Minimal fix plus invariant test that would have caught it.
