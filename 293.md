berndartmueller

medium

# Party B liquidation can expire, causing the liquidation to be stuck

## Summary

The liquidation of Party B can get stuck if the liquidation timeout is reached and the positions are not liquidated within the timeout period.

## Vulnerability Detail

The insolvent Party B's positions are liquidated by the liquidator via the `liquidatePositionsPartyB` function in the `LiquidationFacetImpl` library. This function requires supplying the `QuotePriceSig memory priceSig` parameter, which includes a timestamp and a signature from the Muon app. The signature is verified to ensure the `priceSig` values were actually fetched by the trusted Muon app.

The signature is expected to be created within the liquidation timeout period. This is verified through the validation of the `priceSig.timestamp`, as seen in lines 318-322. Failure to do so, i.e., providing a signature that's created beyond the liquidation timeout, results in the signature being treated as expired, thereby causing the function to revert and rendering the liquidation of Party B stuck.

## Impact

Party A's [locked balance is not decremented by the liquidatable position](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L348). Party B's liquidations status is stuck and remains set to `true`, resulting in the `notLiquidated` and `notLiquidatedPartyB` modifiers to revert.

## Code Snippet

[contracts/facets/liquidation/LiquidationFacetImpl.sol#L318-L322](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L318-L322)

```solidity
308: function liquidatePositionsPartyB(
309:     address partyB,
310:     address partyA,
311:     QuotePriceSig memory priceSig
312: ) internal {
313:     AccountStorage.Layout storage accountLayout = AccountStorage.layout();
314:     MAStorage.Layout storage maLayout = MAStorage.layout();
315:     QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
316:
317:     LibMuon.verifyQuotePrices(priceSig);
318: @>  require(
319: @>      priceSig.timestamp <=
320: @>          maLayout.partyBLiquidationTimestamp[partyB][partyA] + maLayout.liquidationTimeout,
321: @>      "LiquidationFacet: Expired signature"
322: @>  );
323:     require(
324:         maLayout.partyBLiquidationStatus[partyB][partyA],
325:         "LiquidationFacet: PartyB is solvent"
326:     );
327:     require(
328:         block.timestamp <= priceSig.timestamp + maLayout.liquidationTimeout,
329:         "LiquidationFacet: Expired price sig"
330:     );
```

## Tool used

Manual Review

## Recommendation

Consider adding functionality to reset the liquidation status (i.e., `maLayout.partyBLiquidationStatus[partyB][partyA] = false` and `maLayout.partyBLiquidationTimestamp[partyB][partyA] = 0`) of Party B once the liquidation timeout is reached.
