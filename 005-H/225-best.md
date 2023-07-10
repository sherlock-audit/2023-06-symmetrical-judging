xiaoming90

high

# Users might immediately be liquidated after position opening leading to a loss of CVA and Liquidation fee

## Summary

The insolvency check (`isSolventAfterOpenPosition`) within the `openPosition` function does not consider the locked balance adjustment, causing the user account to become insolvent immediately after the position is opened. As a result, the affected users will lose their CVA and liquidation fee locked in their accounts.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L150


```solidity
File: PartyBFacetImpl.sol
112:     function openPosition(
113:         uint256 quoteId,
114:         uint256 filledAmount,
115:         uint256 openedPrice,
116:         PairUpnlAndPriceSig memory upnlSig
117:     ) internal returns (uint256 currentId) {
..SNIP..
150:         LibSolvency.isSolventAfterOpenPosition(quoteId, filledAmount, upnlSig);
151: 
152:         accountLayout.partyANonces[quote.partyA] += 1;
153:         accountLayout.partyBNonces[quote.partyB][quote.partyA] += 1;
154:         quote.modifyTimestamp = block.timestamp;
155: 
156:         LibQuote.removeFromPendingQuotes(quote);
157: 
158:         if (quote.quantity == filledAmount) {
159:             accountLayout.pendingLockedBalances[quote.partyA].subQuote(quote);
160:             accountLayout.partyBPendingLockedBalances[quote.partyB][quote.partyA].subQuote(quote);
161: 
162:             if (quote.orderType == OrderType.LIMIT) {
163:                 quote.lockedValues.mul(openedPrice).div(quote.requestedOpenPrice);
164:             }
165:             accountLayout.lockedBalances[quote.partyA].addQuote(quote);
166:             accountLayout.partyBLockedBalances[quote.partyB][quote.partyA].addQuote(quote);
167:         }
```

The leverage of a position is computed based on the following formula.

$leverage = \frac{price \times quantity}{lockedValues.total()}$

When opening a position, there is a possibility that the leverage might change because the locked values and quantity are fixed, but it could get filled with a different market price compared to the one at the moment the user requested. Thus, the purpose of Line 163 above is to adjust the locked values to maintain a fixed leverage. After the adjustment, the locked value might be higher or lower.

The issue is that the insolvency check at Line 150 is performed before the adjustment is made. 

Assume that the adjustment in Line 163 cause the locked values to increase. The insolvency check (`isSolventAfterOpenPosition`) at Line 150 will be performed with old or unadjusted locked values that are smaller than expected. Since smaller locked values mean that there will be more available balance, this might cause the system to miscalculate that an account is not liquidatable, but in fact, it is actually liquidatable once the adjusted increased locked value is taken into consideration.

In this case, once the position is opened, the user account is immediately underwater and can be liquidated.

The issue will occur in the "complete fill" path and "partial fill" path since both paths adjust the locked values to maintain a fixed leverage. The "complete fill" path adjusts the locked values at [Line 185](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L185)

## Impact

Users might become liquidatable immediately after opening a position due to an incorrect insolvency check within the `openPosition`, which erroneously reports that the account will still be healthy after opening the position, while in reality, it is not. As a result, the affected users will lose their CVA and liquidation fee locked in their accounts.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L150

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L185

## Tool used

Manual Review

## Recommendation

Consider performing the insolvency check with the updated adjusted locked values.