from __future__ import annotations

import re
from pathlib import Path
from .models import ContractInfo, EconomicPrimitive, ProtocolModel

ROLE_PATTERNS = ["owner", "admin", "governor", "guardian", "manager", "keeper", "operator", "pauser", "minter", "burner"]
ASSET_PATTERNS = ["token", "asset", "eth", "weth", "usdc", "usdt", "dai", "share", "vault", "nft", "erc20", "erc721", "erc1155"]
ACCOUNTING_PATTERNS = ["balance", "totalSupply", "totalAssets", "shares", "debt", "credit", "deposit", "withdraw", "stake", "reward", "fee"]
INTEGRATION_PATTERNS = ["oracle", "router", "pool", "vault", "bridge", "chainlink", "pyth", "uniswap", "aave", "euler", "curve"]


def _contains_any(value: str, patterns: list[str]) -> list[str]:
    lower = value.lower()
    return [p for p in patterns if p.lower() in lower]


def build_protocol_model(root: str | Path, contracts: list[ContractInfo]) -> ProtocolModel:
    actors = {"user", "attacker"}
    privileged_roles: set[str] = set()
    assets: set[str] = set()
    accounting: set[str] = set()
    integrations: set[str] = set()
    trust: set[str] = set()
    econ: list[EconomicPrimitive] = []

    for c in contracts:
        for item in [c.name, *c.inherits, *c.state_variables]:
            for p in _contains_any(item, ROLE_PATTERNS):
                privileged_roles.add(p)
                actors.add(p)
            for p in _contains_any(item, ASSET_PATTERNS):
                assets.add(item)
            for p in _contains_any(item, ACCOUNTING_PATTERNS):
                accounting.add(item)
            for p in _contains_any(item, INTEGRATION_PATTERNS):
                integrations.add(item)

        for fn in c.functions:
            fn_text = f"{fn.name} {' '.join(fn.modifiers)} {fn.body}"
            if re.search(r"only[A-Z]|hasRole|require\s*\(.*(owner|admin|role|governor)", fn_text, re.I | re.S):
                trust.add(f"{c.name}.{fn.name} depends on privileged authorization being correct")
            if any(k in fn.name.lower() for k in ["deposit", "withdraw", "mint", "burn", "stake", "claim", "reward"]):
                econ.append(EconomicPrimitive(
                    name=f"{c.name}.{fn.name}",
                    source_of_value=["caller funds", "protocol balance", "reward emissions"] if any(k in fn.name.lower() for k in ["deposit", "stake", "claim", "reward"]) else [],
                    sink_of_value=["user balance", "protocol reserve", "fee recipient"],
                    reward_distribution=[fn.name] if any(k in fn.name.lower() for k in ["claim", "reward", "distribute"]) else [],
                    timing_dependence=["block.timestamp/block.number"] if "block.timestamp" in fn.body or "block.number" in fn.body else [],
                    external_price_dependency=["oracle/price feed"] if re.search(r"price|oracle|getLatest|latestRound", fn.body, re.I) else [],
                ))

    return ProtocolModel(
        root=str(Path(root).resolve()),
        contracts=contracts,
        actors=sorted(actors),
        privileged_roles=sorted(privileged_roles),
        assets=sorted(assets),
        accounting_systems=sorted(accounting),
        integrations=sorted(integrations),
        trust_assumptions=sorted(trust),
        economic_primitives=econ,
    )
