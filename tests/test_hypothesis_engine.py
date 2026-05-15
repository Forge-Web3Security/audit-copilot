from audit_copilot.analysis.hypothesis_engine import generate_hypotheses, hypotheses_to_markdown


def test_generate_hypotheses_for_share_and_reward_paths():
    analysis = {
        "transitions": [
            {
                "contract": "SimpleVault",
                "function": "deposit",
                "reads_storage": ["amount", "asset"],
                "writes_storage": ["assetsBefore", "minted", "shares", "totalShares"],
                "external_calls": ["transferFrom"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
            {
                "contract": "SimpleVault",
                "function": "claimRewards",
                "reads_storage": ["asset", "rewardRate", "shares"],
                "writes_storage": ["amount", "elapsed", "lastClaim"],
                "external_calls": ["transfer"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
        ]
    }

    ids = {h.id for h in generate_hypotheses(analysis)}

    assert "share-manipulation:simplevault-deposit" in ids
    assert "reward-snapshot:simplevault-claimrewards" in ids
    assert "external-call-order:simplevault-claimrewards" in ids


def test_hypotheses_markdown_contains_sections():
    hypotheses = generate_hypotheses(
        {
            "transitions": [
                {
                    "contract": "Vault",
                    "function": "withdraw",
                    "reads_storage": ["shares"],
                    "writes_storage": ["shares", "totalShares"],
                    "external_calls": ["transfer"],
                    "asset_movements": ["token movement/mint/burn"],
                }
            ]
        }
    )
    md = hypotheses_to_markdown(hypotheses)

    assert "# Finding Hypotheses" in md
    assert "Candidate invariant" in md
    assert "Validation steps" in md


def test_precision_filter_drops_noisy_admin_and_entitlement_hypotheses():
    analysis = {
        "transitions": [
            {
                "contract": "SimpleVault",
                "function": "setRewardRate",
                "reads_storage": [],
                "writes_storage": ["rewardRate"],
                "external_calls": [],
                "auth_requirements": ["onlyOwner"],
                "asset_movements": [],
            },
            {
                "contract": "SimpleVault",
                "function": "withdraw",
                "reads_storage": ["asset"],
                "writes_storage": ["amountOut", "shares", "totalShares"],
                "external_calls": ["transfer"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
            {
                "contract": "SimpleVault",
                "function": "claimRewards",
                "reads_storage": ["asset", "rewardRate", "shares"],
                "writes_storage": ["amount", "elapsed", "lastClaim"],
                "external_calls": ["transfer"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
        ]
    }

    ids = {h.id for h in generate_hypotheses(analysis)}

    assert "price-manipulation:simplevault-setrewardrate" not in ids
    assert "reward-snapshot:simplevault-setrewardrate" not in ids
    assert "asset-move-no-auth:simplevault-withdraw" not in ids
    assert "asset-move-no-auth:simplevault-claimrewards" not in ids
    assert "external-call-order:simplevault-withdraw" in ids
    assert "external-call-order:simplevault-claimrewards" in ids
    assert "share-manipulation:simplevault-deposit" not in ids
    assert "share-manipulation:simplevault-withdraw" in ids
    assert "reward-snapshot:simplevault-claimrewards" in ids
    assert "privilege-review:simplevault-setrewardrate" in ids

def test_precision_filter_drops_trusted_admin_accounting_noise():
    analysis = {
        "transitions": [
            {
                "contract": "SimpleVault",
                "function": "setRewardRate",
                "reads_storage": [],
                "writes_storage": ["rewardRate"],
                "external_calls": [],
                "auth_requirements": ["onlyOwner"],
                "asset_movements": [],
            },
            {
                "contract": "SimpleVault",
                "function": "deposit",
                "reads_storage": ["amount", "asset"],
                "writes_storage": ["assetsBefore", "minted", "shares", "totalShares"],
                "external_calls": ["transferFrom"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
            {
                "contract": "SimpleVault",
                "function": "withdraw",
                "reads_storage": ["asset"],
                "writes_storage": ["amountOut", "shares", "totalShares"],
                "external_calls": ["low-level external call", "transfer"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
            {
                "contract": "SimpleVault",
                "function": "claimRewards",
                "reads_storage": ["asset", "rewardRate", "shares"],
                "writes_storage": ["amount", "elapsed", "lastClaim"],
                "external_calls": ["low-level external call", "transfer"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
        ]
    }

    hypotheses = generate_hypotheses(analysis)
    ids = {h.id for h in hypotheses}

    assert "price-manipulation:simplevault-setrewardrate" not in ids
    assert "reward-snapshot:simplevault-setrewardrate" not in ids
    assert "accounting-no-assets:simplevault-setrewardrate" not in ids
    assert "asset-move-no-auth:simplevault-withdraw" not in ids
    assert "asset-move-no-auth:simplevault-claimrewards" not in ids

    assert "privilege-review:simplevault-setrewardrate" in ids
    assert "share-manipulation:simplevault-deposit" in ids
    assert "share-manipulation:simplevault-withdraw" in ids
    assert "reward-snapshot:simplevault-claimrewards" in ids

    deposit_order = next(h for h in hypotheses if h.id == "external-call-order:simplevault-deposit")
    assert deposit_order.severity_guess == "medium"
    assert deposit_order.confidence <= 0.48

def test_v34_primer_backed_vault_archetypes():
    analysis = {
        "transitions": [
            {
                "contract": "SimpleVault",
                "function": "deposit",
                "reads_storage": ["amount", "asset"],
                "writes_storage": ["assetsBefore", "minted", "shares", "totalShares"],
                "external_calls": ["transferFrom"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
            {
                "contract": "SimpleVault",
                "function": "withdraw",
                "reads_storage": ["asset"],
                "writes_storage": ["amountOut", "shares", "totalShares"],
                "external_calls": ["low-level external call", "transfer"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
            {
                "contract": "SimpleVault",
                "function": "claimRewards",
                "reads_storage": ["asset", "rewardRate", "shares"],
                "writes_storage": ["amount", "elapsed", "lastClaim"],
                "external_calls": ["low-level external call", "transfer"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
        ]
    }

    ids = {h.id for h in generate_hypotheses(analysis)}

    assert "fot-accounting-mismatch:simplevault-deposit" in ids
    assert "missing-min-shares:simplevault-deposit" in ids
    assert "reward-insolvency:simplevault-claimrewards" in ids
    assert "withdraw-rounding-dust:simplevault-withdraw" in ids

def test_v35_detects_missing_access_control_owner_setter():
    analysis = {
        "transitions": [
            {
                "contract": "MissingAccessControls",
                "function": "setOwner",
                "visibility": "external",
                "reads_storage": [],
                "writes_storage": ["owner"],
                "external_calls": [],
                "auth_requirements": [],
                "asset_movements": [],
            }
        ]
    }

    ids = {h.id for h in generate_hypotheses(analysis)}

    assert "missing-access-control:missingaccesscontrols-setowner" in ids

def test_v36_detects_oracle_spot_price_manipulation():
    analysis = {
        "transitions": [
            {
                "contract": "BadExchange",
                "function": "getPriceOfUSDCInWeth",
                "visibility": "external",
                "reads_storage": ["i_poolToken", "i_wethToken"],
                "writes_storage": [],
                "external_calls": ["balanceOf", "getOutputAmountBasedOnInput"],
                "auth_requirements": [],
                "asset_movements": [],
            },
            {
                "contract": "OracleManipulation",
                "function": "buyNft",
                "visibility": "external",
                "reads_storage": ["exchange", "USD_PRICE_OF_NFT", "tokenCounter"],
                "writes_storage": ["tokenCounter"],
                "external_calls": ["getEthPriceOfNft"],
                "auth_requirements": [],
                "asset_movements": [],
            },
        ]
    }

    ids = {h.id for h in generate_hypotheses(analysis)}

    assert "oracle-spot-price-manipulation:badexchange-getpriceofusdcinweth" in ids
    assert "oracle-spot-price-manipulation:oraclemanipulation-buynft" in ids
