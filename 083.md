cergyk

high

# Liquidation may incur unbounded shortfall on the protocol

## Summary
During a partyA's liquidation, a partyB can make an unbounded profit, and in the case it is larger than partyA's allocated amount,
the deficit of the quote would be spilling over other market participants. 

## Vulnerability Detail
We can see that during partyA liquidation, the amount of PNL computed for a quote is unbounded, and dependent only on market conditions:
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L152-L156

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L100-L120

And if partyA does not make a profit, this amount is added to the partyB's allocated balances:
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L172

Which means this partyB can later deallocate and withdraw this profit.
Whereas the downside for partyA is bounded since it's allocated funds are only written down to zero:
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L216

This means the protocol incurs a shortfall, but this shortfall is directly spilling onto other users since overall amount of allocated balances has inflated. This means that some users can't withdraw their due funds at some point in the future.

## Impact
Some liquidation conditions for a quote can incur an unbounded shortfall on other users of the protocol. 

## Code Snippet

## Tool used

Manual Review

## Recommendation
Bound partyB's profit to partyA's locked funds for the quote.