rvierdiiev

high

# partyA doesn't receive cva and pnl when partyB is liquidated

## Summary
partyA doesn't receive cva and pnl when partyB is liquidated, because the code is commented.
## Vulnerability Detail
When quote is locked, then both partyA and partyB locked `lf` and `cva` amounts, that are used during liquidations.

When partyB is liquidated, then `cva` is not sent to the partyA. Also pnl is not accounted for the partyA.
The code is [currently commented](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L347-L360).
## Impact
partyA losses cva, pnl is not accrued
## Code Snippet
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L347-L360
## Tool used

Manual Review

## Recommendation
Accrue cva and pnl for the partyA.