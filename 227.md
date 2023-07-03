xiaoming90

high

# Funds could be stolen via sandwich attack against symbol update transaction

## Summary

Malicious users could perform a sandwich attack against the symbol update transaction to steal funds from the protocols

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L122

```solidity
File: LibQuote.sol
122:     function getTradingFee(uint256 quoteId) internal view returns (uint256 fee) {
123:         QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
124:         Quote storage quote = quoteLayout.quotes[quoteId];
125:         Symbol storage symbol = SymbolStorage.layout().symbols[quote.symbolId];
126:         if (quote.orderType == OrderType.LIMIT) {
127:             fee =
128:                 (LibQuote.quoteOpenAmount(quote) * quote.requestedOpenPrice * symbol.tradingFee) /
129:                 1e36;
130:         } else {
131:             fee = (LibQuote.quoteOpenAmount(quote) * quote.marketPrice * symbol.tradingFee) / 1e36;
132:         }
133:     }
134: 
135:     function returnTradingFee(uint256 quoteId) internal {
136:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
137:         uint256 tradingFee = LibQuote.getTradingFee(quoteId);
138:         accountLayout.allocatedBalances[QuoteStorage.layout().quotes[quoteId].partyA] += tradingFee;
139:         accountLayout.balances[GlobalAppStorage.layout().feeCollector] -= tradingFee;
140:     }
```

The amount of trading fee returned to the users is computed dynamically when the `returnTradingFee` function is triggered. In general, the following formula is used to compute the trading fee at any point in time. In the testing script, $TradingFeePercent$ is set to $1\%$.

$Trading Fee = Amount\times Price \times TradingFeePercent$

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L164

```solidity
File: ControlFacet.sol
164:     function setSymbolTradingFee(
165:         uint256 symbolId,
166:         uint256 tradingFee
167:     ) external onlyRole(LibAccessibility.SYMBOL_MANAGER_ROLE) {
168:         SymbolStorage.Layout storage symbolLayout = SymbolStorage.layout();
169:         require(symbolId >= 1 && symbolId <= symbolLayout.lastId, "ControlFacet: Invalid id");
170:         emit SetSymbolTradingFee(symbolId, symbolLayout.symbols[symbolId].tradingFee, tradingFee);
171:         symbolLayout.symbols[symbolId].tradingFee = tradingFee;
172:     }
```

The protocol manager can update the trading fee for a symbol via the `setSymbolTradingFee` function.

When the manager updates the trading for a symbol, a malicious user can perform a sandwich attack against the symbol update transaction to steal funds from the protocols. Following is the proof-of-concept for the attack:

1. Assume that the current `symbol.tradingFee` for `BTCUSDT` symbol is 1%.
2. The manager updates the `symbol.tradingFee` to 3% via the `setSymbolTradingFee` function and submits the symbol update transaction to the blockchain. The transaction appears in the mempool.
3. Bob saw the symbol update transaction in the mempool. He decided to front-run the symbol update transaction by submitting a new position/quote with the largest possible notional value allowed by the protocol. Let's assume he submits a position with a notional value of 1,000,000 USD. In this case, the trading fee will be 10,000 USD (1% of 1,000,000 USD).  
4. Bob also crafts another transaction that cancels the position/quote via the `requestToCancelQuote` function and has this transaction back-run the symbol update transaction.
5. When the create position/quote transaction is executed, 10,000 USD of the trading fee will be pulled from Bob's wallet address and locked in the protocol.
6. Next, the symbol update transaction will be executed, which will update the trading fee for `BTCUSDT` symbol from 1% to 3%
7. Finally, cancels the position/quote transaction will be executed. The trading fee returned is computed on the spot based on the latest trading fee of 3%. Thus, the trading fee returned will be 30,000 USD (3% of 1,000,000 USD)
8. Bob profits 20,000 USD (30,000 USD - 10,000 USD) within a single block.

## Impact

Funds could be stolen from the protocol.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L122

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L164

## Tool used

Manual Review

## Recommendation

Consider keeping track of how much trading fee was being paid in the first place when the position/quote was created. In this example, 10,000 USD of the trading fee is paid by Bob. Thus, the trading fee returned should not end up being more than what he originally paid (10,000 USD)