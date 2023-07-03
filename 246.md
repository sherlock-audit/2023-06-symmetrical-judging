xiaoming90

medium

# Leverage for market orders might deviate

## Summary

The leverage for market orders might deviate as the locked values are not adjusted according to the change in the market price, resulting in unexpected losses.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L112

```solidity
File: PartyBFacetImpl.sol
112:     function openPosition(
113:         uint256 quoteId,
114:         uint256 filledAmount,
115:         uint256 openedPrice,
116:         PairUpnlAndPriceSig memory upnlSig
117:     ) internal returns (uint256 currentId) {
..SNIP..
136:         if (quote.positionType == PositionType.LONG) {
137:             require(
138:                 openedPrice <= quote.requestedOpenPrice,
139:                 "PartyBFacet: Opened price isn't valid"
140:             );
141:         } else {
142:             require(
143:                 openedPrice >= quote.requestedOpenPrice,
144:                 "PartyBFacet: Opened price isn't valid"
145:             );
146:         }
..SNIP..
158:         if (quote.quantity == filledAmount) {
159:             accountLayout.pendingLockedBalances[quote.partyA].subQuote(quote);
160:             accountLayout.partyBPendingLockedBalances[quote.partyB][quote.partyA].subQuote(quote);
161: 
162:             if (quote.orderType == OrderType.LIMIT) {
163:                 quote.lockedValues.mul(openedPrice).div(quote.requestedOpenPrice);
164:             }
```

The leverage of a position is computed based on the following formula.

$leverage = \frac{price \times quantity}{lockedValues.total()}$

When opening a position, there is a possibility that the leverage might change because the locked values and quantity are fixed, but it could get filled with a different market price compared to the one at the moment the user requested.

To ensure that a fixed leverage is maintained, the `quote.lockedValues` is being adjusted proportionally to the `openedPrice`. The `quote.lockedValues` could adjust upward or downward during the adjustment.

However, the issue is that the adjustment is only being performed for limit orders but not for market orders. 

## Impact

The leverage factor of a market order position that is executed on-chain might end up deviating from the one at the moment the user requested due to the fluctuation of the market price. As a result, users might end up opening a position with a leverage factor higher or lower than they originally configured.

The leverage factor determines the extent of exposure to the position; thus, it might potentially magnify losses if a losing position has higher leverage than expected OR lose out on potential gain if a winning position has a lower leverage than expected.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L112

## Tool used

Manual Review

## Recommendation

Consider adjusting locked values for market orders to maintain the leverage, similar to what has been done for the limit orders.