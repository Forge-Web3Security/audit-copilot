Do not weaken benchmark expectations to pass tests.
A failing benchmark is evidence.
Diagnose parser vs detector vs taxonomy vs fixture issue.
Use positive and negative fixtures.
Keep reports healthy: required/forbidden checks, noise watch, full hypotheses.
Prefer 3–5 item production batches.
External model suggestions are advisory; benchmarks and evidence decide.


We are building audit-copilot, a production-grade smart contract audit / bug bounty assistant.

Core rule:
Do not weaken benchmark expectations just to pass tests. If a benchmark fails, diagnose whether the issue is:
- parser weakness
- detector weakness
- taxonomy problem
- fixture design problem
- legitimate false positive / false negative

Then improve the analyzer or fixture with evidence.

Current workflow:
- Work in small batches of 3–5 related changes.
- Every batch must pass pytest and benchmark-fixtures.
- Positive fixtures prove we catch real vulnerability patterns.
- Negative fixtures prove we avoid false positives.
- Reports include Health summary, Required / forbidden checks, Noise watch, and Full observed hypotheses.

Current benchmark status:
- 15 total fixtures
- 15 passing
- 0 failing
- positive fixtures include reentrancy, missing access control, oracle spot price manipulation, ERC4626 first-depositor inflation, signature replay, forced ETH accounting, unbounded-loop DoS, stale oracle price.
- negative fixtures include protected owner setter, virtual offset vault, CEI-safe withdraw, safe TWAP oracle, safe permissionless claim, protected signature claim.

Recent important lesson:
For stale oracle detection, we rejected keyword-only detection. It should not be:
“latestRoundData exists => stale-oracle-price”

It should be:
Chainlink-style oracle round data is read
AND answer/price is used in value-sensitive math or value flow
AND no real freshness/completeness validation exists
AND value flows into state, event, array, accounting, redemption, settlement, claim, liquidation, mint/redeem, or similar.

Oracle taxonomy we want:
- oracle-spot-price-manipulation
- stale-oracle-price
- untrusted-oracle-source
- oracle-decimal-mismatch
- oracle-derived-value-flow

Please help review detector logic, parser logic, benchmark fixture design, and edge cases. Prioritize precision, maintainability, taxonomy clarity, and benchmark integrity.
