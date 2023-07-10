AkshaySrivastav

high

# Protocol operation (including liquidations) can face DoS if `partyAPendingQuotes` grows too large

## Summary
`pendingQuotesValidLength` limit is not implied on `partyAPendingQuotes` array during the new quote creation in `openPosition` function. This array can grow too large causing DoS respective to partyA including liquidations.

## Vulnerability Detail
During the `openPosition` function call, when a position is partially filled, a new quote is created for the same partyA. The new quote's id is pushed into the `partyAPendingQuotes` array without validating the array's length against `pendingQuotesValidLength`.

This array is iterated over in these functions:
- liquidatePendingPositionsPartyA
- liquidatePartyB
- removeFromPartyAPendingQuotes
    - requestToCancelQuote
- removeFromPendingQuotes
    - forceCancelQuote
    - acceptCancelRequest
    - openPosition
- expireQuote
    - expireQuote
    - requestToCancelQuote
    - requestToCancelCloseRequest
    - unlockQuote

All these functions will face risk of DoS

## Impact
This issue can be exploited if both partyA and partyB join forces and want partyA to be resistant to liquidation.

Scenario:
1. PartyA opens multiple positions with different partyBs.
2. PartyA then collaborates with a partyB to open hundreds or thousands of very small positions. This can be done by offering decent incentives.
3. PartyA then sends one quote for partyB.
4. PartyB intensionally opens very small positions against that particular quote, forcing new pending quotes to be pushed to the `partyAPendingQuotes` array.
5. PartyA becomes prone to liquidations.

Note that in this attack all of partyA's positions will become prone to liquidations and not just the positions with that collaborative partyB. Also as the iteration also happens in `liquidatePartyB` function an attack can be crafted to DoS partyB's positions with partyA.

Attack is easier to perform and pushes all partyB's into risk of loosing funds as that particular partyA cannot be liquidated

## Code Snippet
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L176

## Tool used

Manual Review

## Recommendation
While pushing new quote id to `partyAPendingQuotes` in `openPosition` validate the array length against `pendingQuotesValidLength`.