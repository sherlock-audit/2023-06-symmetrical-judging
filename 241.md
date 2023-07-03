xiaoming90

high

# Liquidation of PartyA will fail due to underflow errors

## Summary

Liquidation of PartyA will fail due to underflow errors. As a result, assets will be stuck, and there will be a loss of assets for the counterparty (the creditor) since they cannot receive the liquidated assets.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L126

```solidity
File: LiquidationFacetImpl.sol
126:     function liquidatePositionsPartyA(
127:         address partyA,
128:         uint256[] memory quoteIds
129:     ) internal returns (bool) {
..SNIP..
152:             (bool hasMadeProfit, uint256 amount) = LibQuote.getValueOfQuoteForPartyA(
153:                 accountLayout.symbolsPrices[partyA][quote.symbolId].price,
154:                 LibQuote.quoteOpenAmount(quote),
155:                 quote
156:             );
..SNIP..
163:             if (
164:                 accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NORMAL
165:             ) {
166:                 accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += quote
167:                     .lockedValues
168:                     .cva;
169:                 if (hasMadeProfit) {
170:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;
171:                 } else {
172:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += amount;
173:                 }
174:             } else if (
175:                 accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.LATE
176:             ) {
177:                 accountLayout.partyBAllocatedBalances[quote.partyB][partyA] +=
178:                     quote.lockedValues.cva -
179:                     ((quote.lockedValues.cva * accountLayout.liquidationDetails[partyA].deficit) /
180:                         accountLayout.lockedBalances[partyA].cva);
181:                 if (hasMadeProfit) {
182:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;
183:                 } else {
184:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += amount;
185:                 }
186:             } else if (
187:                 accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.OVERDUE
188:             ) {
189:                 if (hasMadeProfit) {
190:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;
191:                 } else {
192:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] +=
193:                         amount -
194:                         ((amount * accountLayout.liquidationDetails[partyA].deficit) /
195:                             uint256(-accountLayout.liquidationDetails[partyA].totalUnrealizedLoss));
196:                 }
197:             }
```

Assume that at this point, the allocated balance of PartyB (`accountLayout.partyBAllocatedBalances[quote.partyB][partyA]`) only has 1000 USD. 

In Line 152 above, the `getValueOfQuoteForPartyA` function is called to compute the PnL of a position. Assume the position has a huge profit of 3000 USD due to a sudden spike in price. For this particular position, PartyA will profit 3000 USD while PartyB will lose 3000 USD.

In this case, 3000 USD needs to be deducted from PartyB's account. However, when the `accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;` code at Line 170, 182, or 190 gets executed, an underflow error will occur, and the transaction will revert. This is because `partyBAllocatedBalances` is an unsigned integer, and PartyB only has 1000 USD of allocated balance, but the code attempts to deduct 3000 USD.

## Impact

Liquidation of PartyA will fail. Since liquidation cannot be completed, the assets that are liable to be liquidated cannot be transferred from PartyA (the debtor) to the counterparty (the creditor). Assets will be stuck, and there will be a loss of assets for the counterparty (the creditor) since they cannot receive the liquidated assets.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L126

## Tool used

Manual Review

## Recommendation

Consider implementing the following fixes to ensure that the amount to be deducted will never exceed the allocated balance of PartyB to prevent underflow errors from occurring.

```diff
if (hasMadeProfit) {
+	amountToDeduct = amount > accountLayout.partyBAllocatedBalances[quote.partyB][partyA] ? accountLayout.partyBAllocatedBalances[quote.partyB][partyA] : amount
+ 	accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amountToDeduct
-    accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;
} else {
    accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += amount;
}
```