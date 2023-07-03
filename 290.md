berndartmueller

medium

# Liquidating a turned solvent Party A does not credit the profits to Party A

## Summary

Party A can turn solvent again mid-way through the multi-step liquidation process. While Party B will have its [losses deducted from its allocated balance](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L170), Party A will not receive any profits. Instead, its allocated balance is [reset to 0](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L216).

## Vulnerability Detail

If Party A turns solvent again, i.e., its available balance (`availableBalance`) is positive, after a liquidator has started the liquidation and calls the `setSymbolsPrice` to initialize the symbol prices as well as Party A's liquidation details, the liquidation will proceed as usual. Liquidating the individual open positions of Party A with the `liquidatePositionsPartyA` function deducts the losses from the trading counterparty B's allocated balance in line 170.

However, the profits made by Party A are not credited to Party A's allocated balance. Instead, Party A's allocated balance is reset to 0 in line 216 once all positions are liquidated.

## Impact

Party A's realized profits during the liquidation are retained by the protocol instead of credited to Party A's allocated balance.

## Code Snippet

[contracts/facets/liquidation/LiquidationFacetImpl.sol#L65-L67](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L65-L67)

Party A, who turned solvent, will have the liquidation proceed as usual, with the `liquidationType` set to `NORMAL`.

```solidity
34: function setSymbolsPrice(address partyA, PriceSig memory priceSig) internal {
...     // [...]
51:
52:     int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
53:         priceSig.upnl,
54:         partyA
55:     );
56:     if (accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NONE) {
57:         accountLayout.liquidationDetails[partyA] = LiquidationDetail({
58:             liquidationType: LiquidationType.NONE,
59:             upnl: priceSig.upnl,
60:             totalUnrealizedLoss: priceSig.totalUnrealizedLoss,
61:             deficit: 0,
62:             liquidationFee: 0
63:         });
64: @>      if (availableBalance >= 0) {
65: @>          uint256 remainingLf = accountLayout.lockedBalances[partyA].lf;
66: @>          accountLayout.liquidationDetails[partyA].liquidationType = LiquidationType.NORMAL;
67: @>          accountLayout.liquidationDetails[partyA].liquidationFee = remainingLf;
68:         } else if (uint256(-availableBalance) < accountLayout.lockedBalances[partyA].lf) {
...     // [...]
97: }
```

[contracts/facets/liquidation/LiquidationFacetImpl.sol#L170](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L170)

Liquidating Party A's positions, which are in a profit (and thus a loss for Party B), deducts the losses from Party B's allocated balance in line 170. The profit is **not** credited to Party A.

```solidity
File: LiquidationFacetImpl.sol
126: function liquidatePositionsPartyA(
127:     address partyA,
128:     uint256[] memory quoteIds
129: ) internal returns (bool) {
130:     AccountStorage.Layout storage accountLayout = AccountStorage.layout();
131:     MAStorage.Layout storage maLayout = MAStorage.layout();
132:     QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
133:
134:     require(maLayout.liquidationStatus[partyA], "LiquidationFacet: PartyA is solvent");
135:     for (uint256 index = 0; index < quoteIds.length; index++) {
136:         Quote storage quote = quoteLayout.quotes[quoteIds[index]];
...          // [...]
162:
163:         if (
164:             accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NORMAL
165:         ) {
166:             accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += quote
167:                 .lockedValues
168:                 .cva;
169:             if (hasMadeProfit) {
170: @>              accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount; // @audit-info Party B's allocated balance is decreased by the amount of profit made by party A
171:             } else {
172:                 accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += amount;
173:             }
```

[contracts/facets/liquidation/LiquidationFacetImpl.sol#L216](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L216)

Once all of Party A's positions are liquidated, Party A's allocated balance is reset to 0 in line 216.

```solidity
126: function liquidatePositionsPartyA(
127:     address partyA,
128:     uint256[] memory quoteIds
129: ) internal returns (bool) {
...   // [...]
211:  if (quoteLayout.partyAPositionsCount[partyA] == 0) {
212:      require(
213:          quoteLayout.partyAPendingQuotes[partyA].length == 0,
214:          "LiquidationFacet: Pending quotes should be liquidated first"
215:      );
216:  @>  accountLayout.allocatedBalances[partyA] = 0;
217:      accountLayout.lockedBalances[partyA].makeZero();
218:
219:      uint256 lf = accountLayout.liquidationDetails[partyA].liquidationFee;
220:      if (lf > 0) {
221:          accountLayout.allocatedBalances[accountLayout.liquidators[partyA][0]] += lf / 2;
222:          accountLayout.allocatedBalances[accountLayout.liquidators[partyA][1]] += lf / 2;
223:      }
224:      delete accountLayout.liquidators[partyA];
225:      maLayout.liquidationStatus[partyA] = false;
226:      maLayout.liquidationTimestamp[partyA] = 0;
227:      accountLayout.liquidationDetails[partyA].liquidationType = LiquidationType.NONE;
228:      if (
229:          accountLayout.totalUnplForLiquidation[partyA] !=
230:          accountLayout.liquidationDetails[partyA].upnl
231:      ) {
232:          accountLayout.totalUnplForLiquidation[partyA] = 0;
233:          return false;
234:      }
235:      accountLayout.totalUnplForLiquidation[partyA] = 0;
236:  }
237:  return true;
```

## Tool used

Manual Review

## Recommendation

Consider adding Party A's realized profits during the liquidation to Party A's allocated balance.
