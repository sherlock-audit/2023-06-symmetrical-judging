xiaoming90

high

# `emergencyClosePosition` can be blocked

## Summary

The `emergencyClosePosition` function can be blocked as PartyA can change the position's status, which causes the transaction to revert when executed.

## Vulnerability Detail

Activating the emergency mode can be done either for a specific PartyB or for the entire system. Once activated, PartyB gains the ability to swiftly close positions without requiring users' requests. This functionality is specifically designed to cater to urgent situations where PartyBs must promptly close their positions.

Based on the `PartyBFacetImpl.emergencyClosePosition` function, a position can only be "emergency" close if its status is `QuoteStatus.OPENED`.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L312

```solidity
File: PartyBFacetImpl.sol
309:     function emergencyClosePosition(uint256 quoteId, PairUpnlAndPriceSig memory upnlSig) internal {
310:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
311:         Quote storage quote = QuoteStorage.layout().quotes[quoteId];
312:         require(quote.quoteStatus == QuoteStatus.OPENED, "PartyBFacet: Invalid state");
..SNIP..
```

As a result, if PartyA knows that emergency mode has been activated, PartyA could pre-emptively call the `PartyAFacetImpl.requestToClosePosition` with minimum possible `quantityToClose` (e.g. 1 wei) against their positions to change the state to `QuoteStatus.CLOSE_PENDING` so that the `PartyBFacetImpl.emergencyClosePosition` function will always revert when triggered by PartyB. This effectively blocks PartyB from "emergency" close the positions in urgent situations. 

PartyA could also block PartyB "emergency" close on-demand by front-running PartyB's `PartyBFacetImpl.emergencyClosePosition` transaction with the `PartyAFacetImpl.requestToClosePosition` with minimum possible `quantityToClose` (e.g. 1 wei) when detected.

PartyB could accept the close position request of 1 wei to revert the quote's status back to `QuoteStatus.OPENED` and try to perform an "emergency" close again. However, a sophisticated malicious user could front-run PartyA to revert the quote's status back to `QuoteStatus.CLOSE_PENDING` again to block the "emergency" close for a second time.

## Impact

During urgent situations where emergency mode is activated, the positions need to be promptly closed to avoid negative events that could potentially lead to serious loss of funds (e.g. the protocol is compromised, and the attacker is planning to or has started draining funds from the protocols). However, if the emergency closure of positions is blocked or delayed, it might lead to unrecoverable losses.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L312

## Tool used

Manual Review

## Recommendation

Update the `emergencyClosePosition` so that the "emergency" close can still proceed even if the position's status is `QuoteStatus.CLOSE_PENDING`.

```diff
function emergencyClosePosition(uint256 quoteId, PairUpnlAndPriceSig memory upnlSig) internal {
        AccountStorage.Layout storage accountLayout = AccountStorage.layout();
        Quote storage quote = QuoteStorage.layout().quotes[quoteId];
-		require(quote.quoteStatus == QuoteStatus.OPENED, "PartyBFacet: Invalid state");
+		require(quote.quoteStatus == QuoteStatus.OPENED || quote.quoteStatus == QuoteStatus.CLOSE_PENDING, "PartyBFacet: Invalid state");
..SNIP..
```