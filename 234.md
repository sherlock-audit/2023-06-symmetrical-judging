xiaoming90

high

# Liquidators will not be incentivized to liquidate certain PartyB accounts due to the lack of incentives

## Summary

Liquidating certain accounts does not provide a liquidation fee to the liquidators. Liquidators will not be incentivized to liquidate such accounts, which may lead to liquidation being delayed or not performed, exposing Party B to unnecessary risks and potentially resulting in greater asset losses than anticipated.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L269

```solidity
File: LiquidationFacetImpl.sol
240:     function liquidatePartyB(
..SNIP..
259:         if (uint256(-availableBalance) < accountLayout.partyBLockedBalances[partyB][partyA].lf) {
260:             remainingLf =
261:                 accountLayout.partyBLockedBalances[partyB][partyA].lf -
262:                 uint256(-availableBalance);
263:             liquidatorShare = (remainingLf * maLayout.liquidatorShare) / 1e18;
264: 
265:             maLayout.partyBPositionLiquidatorsShare[partyB][partyA] =
266:                 (remainingLf - liquidatorShare) /
267:                 quoteLayout.partyBPositionsCount[partyB][partyA];
268:         } else {
269:             maLayout.partyBPositionLiquidatorsShare[partyB][partyA] = 0;
270:         }
```

Assume that the loss of Party B is more than the liquidation fee. In this case, the else branch of the above code within the `liquidatePartyB` function will be executed. The `liquidatorShare` and `partyBPositionLiquidatorsShare` variables will both be zero, which means the liquidators will get nothing in return for liquidating PartyBs

As a result, there will not be any incentive for the liquidators to liquidate such positions.

## Impact

Liquidators will not be incentivized to liquidate those accounts that do not provide them with a liquidation fee. As a result, the liquidation of those accounts might be delayed or not performed at all. When liquidation is not performed in a timely manner, PartyB ended up taking on additional unnecessary risks that could be avoided in the first place if a different liquidation incentive mechanism is adopted, potentially leading to PartyB losing more assets than expected.

Although PartyBs are incentivized to perform liquidation themselves since it is the PartyBs that take on the most risks from the late liquidation, the roles of PartyB and liquidator are clearly segregated in the protocol design. Only addresses granted the role of liquidators can perform liquidation as the liquidation functions are guarded by `onlyRole(LibAccessibility.LIQUIDATOR_ROLE)`. Unless the contracts are implemented in a manner that automatically grants a liquidator role to all new PartyB upon registration OR liquidation functions are made permissionless, PartyBs are likely not able to perform the liquidation themselves when the need arises.

Moreover, the PartyBs are not expected to be both a hedger and liquidator simultaneously as they might not have the skillset or resources to maintain an infrastructure for monitoring their accounts/positions for potential late liquidation.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L269

## Tool used

Manual Review

## Recommendation

Considering updating the liquidation incentive mechanism that will always provide some incentive for the liquidators to take the initiative to liquidate insolvent accounts. This will help to build a more robust and efficient liquidation mechanism for the protocols. One possible approach is to always give a percentage of the CVA of the liquidated account as a liquidation fee to the liquidators.