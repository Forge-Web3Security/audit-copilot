# Audit Copilot Benchmark Results

## Health summary

- **Passed:** 11
- **Failed:** 0
- **Total:** 11
- **Positive fixtures:** 8
- **Negative fixtures:** 3
- **Mixed fixtures:** 0

## Required / forbidden checks

| Fixture | Type | Status | Matched | Missing | Forbidden hit |
|---|---|---:|---|---|---|
| sample-vault | positive | PASS | external-call-order, share-manipulation, reward-insolvency, missing-min-shares | - | - |
| reentrancy | positive | PASS | external-call-order | - | - |
| missing-access-controls | positive | PASS | missing-access-control | - | - |
| oracle-manipulation | positive | PASS | oracle-spot-price-manipulation | - | - |
| protected-owner-setter | negative | PASS | - | - | - |
| first-depositor-inflation | positive | PASS | share-manipulation, missing-min-shares | - | - |
| virtual-offset-vault | negative | PASS | - | - | - |
| cei-safe-withdraw | negative | PASS | - | - | - |
| signature-replay | positive | PASS | signature-replay | - | - |
| forced-eth-accounting | positive | PASS | forced-eth-accounting | - | - |
| dos-unbounded-loop | positive | PASS | dos-unbounded-loop | - | - |

## Noise watch

Non-required hypotheses are not automatically wrong, but they are useful for tracking detector noise as the benchmark grows.

| Fixture | Non-required observed hypotheses |
|---|---|
| sample-vault | `fot-accounting-mismatch:simplevault-deposit`, `privilege-review:simplevault-setrewardrate`, `reward-snapshot:simplevault-claimrewards`, `withdraw-rounding-dust:simplevault-withdraw` |
| reentrancy | - |
| missing-access-controls | - |
| oracle-manipulation | `external-call-order:badexchange-swapexactinput`, `share-manipulation:badexchange-getpriceofonewethinusdc`, `share-manipulation:badexchange-getpriceofusdcinweth`, `share-manipulation:badexchange-swapexactinput` |
| protected-owner-setter | `privilege-review:protectedownersetter-setowner` |
| first-depositor-inflation | `external-call-order:vulnerablevault-redeem` |
| virtual-offset-vault | `external-call-order:safevirtualoffsetvault-redeem`, `share-manipulation:safevirtualoffsetvault-_burn`, `share-manipulation:safevirtualoffsetvault-_mint`, `share-manipulation:safevirtualoffsetvault-converttoassets`, `share-manipulation:safevirtualoffsetvault-converttoshares`, `share-manipulation:safevirtualoffsetvault-deposit`, `share-manipulation:safevirtualoffsetvault-previewdeposit`, `share-manipulation:safevirtualoffsetvault-previewredeem`, `share-manipulation:safevirtualoffsetvault-redeem`, `share-manipulation:safevirtualoffsetvault-totalassets` |
| cei-safe-withdraw | - |
| signature-replay | `asset-move-no-auth:signaturereplayclaim-claim` |
| forced-eth-accounting | - |
| dos-unbounded-loop | - |

## Full observed hypotheses

Use this section for detector debugging. The pass/fail gate is the required/forbidden table above.

### sample-vault
- Required: external-call-order, share-manipulation, reward-insolvency, missing-min-shares
- `external-call-order:simplevault-deposit`
- `external-call-order:simplevault-withdraw`
- `fot-accounting-mismatch:simplevault-deposit`
- `missing-min-shares:simplevault-deposit`
- `privilege-review:simplevault-setrewardrate`
- `reward-insolvency:simplevault-claimrewards`
- `reward-snapshot:simplevault-claimrewards`
- `share-manipulation:simplevault-deposit`
- `share-manipulation:simplevault-withdraw`
- `withdraw-rounding-dust:simplevault-withdraw`

### reentrancy
- Required: external-call-order
- `external-call-order:reentrancyvictim-withdrawbalance`

### missing-access-controls
- Required: missing-access-control
- `missing-access-control:missingaccesscontrols-setowner`

### oracle-manipulation
- Required: oracle-spot-price-manipulation
- `external-call-order:badexchange-swapexactinput`
- `oracle-spot-price-manipulation:badexchange-getoutputamountbasedoninput`
- `oracle-spot-price-manipulation:badexchange-getpriceofonewethinusdc`
- `oracle-spot-price-manipulation:badexchange-getpriceofusdcinweth`
- `oracle-spot-price-manipulation:badexchange-swapexactinput`
- `oracle-spot-price-manipulation:oraclemanipulation-buynft`
- `oracle-spot-price-manipulation:oraclemanipulation-getethpriceofnft`
- `share-manipulation:badexchange-getpriceofonewethinusdc`
- `share-manipulation:badexchange-getpriceofusdcinweth`
- `share-manipulation:badexchange-swapexactinput`

### protected-owner-setter
- Forbidden: missing-access-control
- `privilege-review:protectedownersetter-setowner`

### first-depositor-inflation
- Required: share-manipulation, missing-min-shares
- `external-call-order:vulnerablevault-redeem`
- `missing-min-shares:vulnerablevault-deposit`
- `share-manipulation:vulnerablevault-_burn`
- `share-manipulation:vulnerablevault-_mint`
- `share-manipulation:vulnerablevault-converttoassets`
- `share-manipulation:vulnerablevault-converttoshares`
- `share-manipulation:vulnerablevault-deposit`
- `share-manipulation:vulnerablevault-previewdeposit`
- `share-manipulation:vulnerablevault-previewredeem`
- `share-manipulation:vulnerablevault-redeem`
- `share-manipulation:vulnerablevault-totalassets`

### virtual-offset-vault
- Forbidden: missing-min-shares
- `external-call-order:safevirtualoffsetvault-redeem`
- `share-manipulation:safevirtualoffsetvault-_burn`
- `share-manipulation:safevirtualoffsetvault-_mint`
- `share-manipulation:safevirtualoffsetvault-converttoassets`
- `share-manipulation:safevirtualoffsetvault-converttoshares`
- `share-manipulation:safevirtualoffsetvault-deposit`
- `share-manipulation:safevirtualoffsetvault-previewdeposit`
- `share-manipulation:safevirtualoffsetvault-previewredeem`
- `share-manipulation:safevirtualoffsetvault-redeem`
- `share-manipulation:safevirtualoffsetvault-totalassets`

### cei-safe-withdraw
- Forbidden: external-call-order
- No hypotheses generated

### signature-replay
- Required: signature-replay
- `asset-move-no-auth:signaturereplayclaim-claim`
- `signature-replay:signaturereplayclaim-claim`

### forced-eth-accounting
- Required: forced-eth-accounting
- `forced-eth-accounting:forcedethaccountingvault-withdrawall`

### dos-unbounded-loop
- Required: dos-unbounded-loop
- `dos-unbounded-loop:unboundedloopwithdrawal-withdrawalldepositors`
