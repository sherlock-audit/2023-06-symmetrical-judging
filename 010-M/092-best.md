rvierdiiev

medium

# In case if trading fee will be changed then refund will be done with wrong amount

## Summary
In case if trading fee will be changed then refund will be done with wrong amount 
## Vulnerability Detail
When user creates quote, then he [pays trading fees](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L119). Amount that should be paid is calculated [inside `LibQuote.getTradingFee` function](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L144).

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L122-L133
```soldity
    function getTradingFee(uint256 quoteId) internal view returns (uint256 fee) {
        QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
        Quote storage quote = quoteLayout.quotes[quoteId];
        Symbol storage symbol = SymbolStorage.layout().symbols[quote.symbolId];
        if (quote.orderType == OrderType.LIMIT) {
            fee =
                (LibQuote.quoteOpenAmount(quote) * quote.requestedOpenPrice * symbol.tradingFee) /
                1e36;
        } else {
            fee = (LibQuote.quoteOpenAmount(quote) * quote.marketPrice * symbol.tradingFee) / 1e36;
        }
    }
```

As you can see `symbol.tradingFee` is used to determine fee amount. This fee [can be changed any time](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L164-L172).

When order is canceled, then [fee should be returned to user](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L136). This function also uses [`LibQuote.getTradingFee` function](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L137) to calculate fee to return.

So in case if order was created before fee changes, then returned amount will be not same, when it is canceled after fee changes.
## Impact
User or protocol losses portion of funds.
## Code Snippet
Provided above
## Tool used

Manual Review

## Recommendation
You can store fee paid by user inside quote struct. And when canceled return that amount.