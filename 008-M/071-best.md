Ruhum

high

# Liquidating pending quotes doesn't return trading fee to party A

## Summary
When a user is liquidated, the trading fees of the pending quotes aren't returned.

## Vulnerability Detail
When a pending/locked quote is canceled, the trading fee is sent back to party A, e.g.
- https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L136
- https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L227

But, when a pending quote is liquidated, the trading fee is not used for the liquidation. Instead, the fee collector keeps the funds:

```sol
    function liquidatePendingPositionsPartyA(address partyA) internal {
        QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
        require(
            MAStorage.layout().liquidationStatus[partyA],
            "LiquidationFacet: PartyA is solvent"
        );
        for (uint256 index = 0; index < quoteLayout.partyAPendingQuotes[partyA].length; index++) {
            Quote storage quote = quoteLayout.quotes[
                quoteLayout.partyAPendingQuotes[partyA][index]
            ];
            if (
                (quote.quoteStatus == QuoteStatus.LOCKED ||
                    quote.quoteStatus == QuoteStatus.CANCEL_PENDING) &&
                quoteLayout.partyBPendingQuotes[quote.partyB][partyA].length > 0
            ) {
                delete quoteLayout.partyBPendingQuotes[quote.partyB][partyA];
                AccountStorage
                .layout()
                .partyBPendingLockedBalances[quote.partyB][partyA].makeZero();
            }
            quote.quoteStatus = QuoteStatus.LIQUIDATED;
            quote.modifyTimestamp = block.timestamp;
        }
        AccountStorage.layout().pendingLockedBalances[partyA].makeZero();
        delete quoteLayout.partyAPendingQuotes[partyA];
    }
```

```sol
    function liquidatePartyB(
        address partyB,
        address partyA,
        SingleUpnlSig memory upnlSig
    ) internal {
        // ...
        uint256[] storage pendingQuotes = quoteLayout.partyAPendingQuotes[partyA];

        for (uint256 index = 0; index < pendingQuotes.length; ) {
            Quote storage quote = quoteLayout.quotes[pendingQuotes[index]];
            if (
                quote.partyB == partyB &&
                (quote.quoteStatus == QuoteStatus.LOCKED ||
                    quote.quoteStatus == QuoteStatus.CANCEL_PENDING)
            ) {
                accountLayout.pendingLockedBalances[partyA].subQuote(quote);

                pendingQuotes[index] = pendingQuotes[pendingQuotes.length - 1];
                pendingQuotes.pop();
                quote.quoteStatus = QuoteStatus.LIQUIDATED;
                quote.modifyTimestamp = block.timestamp;
            } else {
                index++;
            }
        }
```

These funds should be used to cover the liquidation. Since no trade has been executed, the fee collector shouldn't earn anything.

## Impact
Liquidation doesn't use paid trading fees to cover outstanding balances. Instead, the funds are kept by the fee collector.

## Code Snippet
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L105-L120
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L277-L293
## Tool used

Manual Review

## Recommendation
return the funds to party A. If party A is being liquidated, use the funds to cover the liquidation. Otherwise, party A keeps the funds.
