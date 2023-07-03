xiaoming90

medium

# Position value can fall below the minimum acceptable quote value

## Summary

PartyB can fill a LIMIT order position till the point where the value is below the minimum acceptable quote value (`minAcceptableQuoteValue`). As a result, it breaks the invariant that the value of position must be above the minimum acceptable quote value, leading to various issues and potentially losses for the users.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L196

```solidity
File: LibQuote.sol
149:     function closeQuote(Quote storage quote, uint256 filledAmount, uint256 closedPrice) internal {
..SNIP..
189:         if (quote.closedAmount == quote.quantity) {
190:             quote.quoteStatus = QuoteStatus.CLOSED;
191:             quote.requestedClosePrice = 0;
192:             removeFromOpenPositions(quote.id);
193:             quoteLayout.partyAPositionsCount[quote.partyA] -= 1;
194:             quoteLayout.partyBPositionsCount[quote.partyB][quote.partyA] -= 1;
195:         } else if (
196:             quote.quoteStatus == QuoteStatus.CANCEL_CLOSE_PENDING || quote.quantityToClose == 0
197:         ) {
198:             quote.quoteStatus = QuoteStatus.OPENED;
199:             quote.requestedClosePrice = 0;
200:             quote.quantityToClose = 0; // for CANCEL_CLOSE_PENDING status
201:         } else {
202:             require(
203:                 quote.lockedValues.total() >=
204:                     SymbolStorage.layout().symbols[quote.symbolId].minAcceptableQuoteValue,
205:                 "LibQuote: Remaining quote value is low"
206:             );
207:         }
208:     }
```

If the user has already sent the close request, but partyB has not filled it yet, the user can request to cancel it by calling the `CancelCloseRequest` function. This will cause the quote's status to change to `QuoteStatus.CANCEL_CLOSE_PENDING`.

PartyB can either accept the cancel request or fill the close request ignoring the user's request. If PartyB decided to go ahead to fill the close request partially, the second branch of the if-else statement at Line 196 will be executed. However, the issue is that within this branch, PartyB is not subjected to the `minAcceptableQuoteValue` validation check. Thus, it is possible for PartyB to fill a LIMIT order position till the point where the value is below the minimum acceptable quote value (`minAcceptableQuoteValue`).

## Impact

In the codebase, the `minAcceptableQuoteValue` is currently set to 5 USD. There are many reasons for having a minimum quote value in the first place. For instance, if the value of a position is too low, it will be uneconomical for the liquidator to liquidate the position because the liquidation fee would be too small or insufficient to cover the cost of liquidation. Note that the liquidation fee is computed as a percentage of the position value.

This has a negative impact on the overall efficiency of the liquidation mechanism within the protocol, which could delay or stop the liquidation of accounts or positions, exposing users to greater market risks, including the risk of incurring larger losses or having to exit at an unfavorable price. 

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L196

## Tool used

Manual Review

## Recommendation

If the user sends a close request and PartyB decides to go ahead to fill the close request partially, consider checking if the remaining value of the position is above the minimum acceptable quote value (`minAcceptableQuoteValue`) after PartyB has filled the position.

```diff
function closeQuote(Quote storage quote, uint256 filledAmount, uint256 closedPrice) internal {
	..SNIP..
    if (quote.closedAmount == quote.quantity) {
        quote.quoteStatus = QuoteStatus.CLOSED;
        quote.requestedClosePrice = 0;
        removeFromOpenPositions(quote.id);
        quoteLayout.partyAPositionsCount[quote.partyA] -= 1;
        quoteLayout.partyBPositionsCount[quote.partyB][quote.partyA] -= 1;
    } else if (
        quote.quoteStatus == QuoteStatus.CANCEL_CLOSE_PENDING || quote.quantityToClose == 0
    ) {
        quote.quoteStatus = QuoteStatus.OPENED;
        quote.requestedClosePrice = 0;
        quote.quantityToClose = 0; // for CANCEL_CLOSE_PENDING status
+        
+        require(
+            quote.lockedValues.total() >=
+                SymbolStorage.layout().symbols[quote.symbolId].minAcceptableQuoteValue,
+            "LibQuote: Remaining quote value is low"
+        );
    } else {
        require(
            quote.lockedValues.total() >=
                SymbolStorage.layout().symbols[quote.symbolId].minAcceptableQuoteValue,
            "LibQuote: Remaining quote value is low"
        );
    }
}
```