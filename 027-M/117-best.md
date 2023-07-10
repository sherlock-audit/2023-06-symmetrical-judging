rvierdiiev

medium

# Locked position shoud become Pending when partyB is liquidated

## Summary
Locked position should become Pending when partyB is liquidated. Otherwise partyA should create new quote and pay gas for that.
## Vulnerability Detail
In case if position is locked and partyB unlocks it, then position becomes [pending again](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L51), so user should not recreate it and another partyB now can lock it.

But in case if partyB is liquidated and quote is locked, then it's set to [liquidated state](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L51).

That means that user should recreate it again and spend more gas on it.
## Impact
user should recreate quote again and spend more gas on it
## Code Snippet
Provided above
## Tool used

Manual Review

## Recommendation
Set locked quote to pending state.