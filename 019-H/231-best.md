xiaoming90

high

# Imbalanced approach of distributing the liquidation fee within `setSymbolsPrice` function

## Summary

The imbalance approach of distributing the liquidation fee within `setSymbolsPrice` function could be exploited by malicious liquidators to obtain the liquidation fee without completing their tasks and maximizing their gains. While doing so, it causes harm or losses to other parties within the protocols.

## Vulnerability Detail

A PartyA can own a large number of different symbols in its portfolio. To avoid out-of-gas (OOG) errors from occurring during liquidation, the `setSymbolsPrice` function allows the liquidators to inject the price of the symbols in multiple transactions instead of all in one go.

Assume that the injection of the price symbols requires 5 transactions/rounds to complete and populate the price of all the symbols in a PartyA's portfolio. Based on the current implementation, only the first liquidator that calls the `setSymbolsPrice` will receive the liquidation fee. Liquidators that call the `setSymbolsPrice` function subsequently will not be added to the `AccountStorage.layout().liquidators[partyA]` listing as Line 88 will only be executed once when the `liquidationType` is still not initialized yet.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L34

```solidity
File: LiquidationFacetImpl.sol
34:     function setSymbolsPrice(address partyA, PriceSig memory priceSig) internal {
..SNIP..
56:         if (accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NONE) {
57:             accountLayout.liquidationDetails[partyA] = LiquidationDetail({
58:                 liquidationType: LiquidationType.NONE,
59:                 upnl: priceSig.upnl,
60:                 totalUnrealizedLoss: priceSig.totalUnrealizedLoss,
61:                 deficit: 0,
62:                 liquidationFee: 0
63:             });
..SNIP..
88:             AccountStorage.layout().liquidators[partyA].push(msg.sender);
89:         } else {
90:             require(
91:                 accountLayout.liquidationDetails[partyA].upnl == priceSig.upnl &&
92:                     accountLayout.liquidationDetails[partyA].totalUnrealizedLoss ==
93:                     priceSig.totalUnrealizedLoss,
94:                 "LiquidationFacet: Invalid upnl sig"
95:             );
96:         }
97:     }
```

A malicious liquidator could take advantage of this by only setting the symbol prices for the first round for each liquidation happening in the protocol. To maximize their profits, the malicious liquidator would call the `setSymbolsPrice` with none or only one (1) symbol price to save on the gas cost. The malicious liquidator would then leave it to the others to complete the rest of the liquidation process, and they will receive half of the liquidation fee at the end of the liquidation process.

Someone would eventually need to step in to complete the liquidation process. Even if none of the liquidators is incentivized to complete the process of setting the symbol prices since they will not receive any liquidation fee, the counterparty would eventually have no choice but to step in to perform the liquidation themselves. Otherwise, the profits of the counterparty cannot be realized. At the end of the day, the liquidation will be completed, and the malicious liquidator will still receive the liquidation fee.

## Impact

Malicious liquidators could exploit the liquidation process to obtain the liquidation fee without completing their tasks and maximizing their gains. While doing so, many liquidations would be stuck halfway since it is likely that no other liquidators will step in to complete the setting of the symbol prices because they will not receive any liquidation fee for doing so (not incentivized).

This could potentially lead to the loss of assets for various parties:

- The counterparty would eventually have no choice but to step in to perform the liquidation themselves. The counterparty has to pay for its own liquidation, even though it has already paid half the liquidation fee to the liquidator.
- Many liquidations would be stuck halfway, and liquidation might be delayed, which exposes users to greater market risks, including the risk of incurring larger losses or having to exit at an unfavorable price. 

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L34

## Tool used

Manual Review

## Recommendation

Consider a more balanced approach for distributing the liquidation fee for liquidators that calls the `setSymbolsPrice` function. For instance, the liquidators should be compensated based on the number of symbol prices they have injected. 

If there are 10 symbols to be filled up, if Bob filled up 4 out of 10 symbols, he should only receive 40% of the liquidation fee. This approach has already been implemented within the `liquidatePartyB` function via the `partyBPositionLiquidatorsShare` variable. Thus, the same design could be retrofitted into the `setSymbolsPrice` function.