xiaoming90

high

# Unrealized profit and loss (uPnL) signature (`upnlSig`) can be re-used and replayed as nonce is not incremented

## Summary

The unrealized profit and loss (uPnL) signature (`upnlSig`) can be re-used and replayed as nonce is not incremented within the `LiquidationFacetImpl.liquidatePartyA` and `LiquidationFacetImpl.liquidatePartyB` functions.

## Vulnerability Detail

Both the `LiquidationFacetImpl.liquidatePartyA` and `LiquidationFacetImpl.liquidatePartyB` functions accept an unrealized profit and loss (uPnL) signature (`upnlSig`) and utilize it to compute the available balance of PartyA or PartyB

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L20

```solidity
File: LiquidationFacetImpl.sol
20:     function liquidatePartyA(address partyA, SingleUpnlSig memory upnlSig) internal {
21:         MAStorage.Layout storage maLayout = MAStorage.layout();
22: 
23:         LibMuon.verifyPartyAUpnl(upnlSig, partyA);
24:         int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
25:             upnlSig.upnl,
26:             partyA
27:         );
28:         require(availableBalance < 0, "LiquidationFacet: PartyA is solvent");
29:         maLayout.liquidationStatus[partyA] = true;
30:         maLayout.liquidationTimestamp[partyA] = upnlSig.timestamp;
31:         AccountStorage.layout().liquidators[partyA].push(msg.sender);
32:     }
```

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L240

```solidity
File: LiquidationFacetImpl.sol
240:     function liquidatePartyB(
241:         address partyB,
242:         address partyA,
243:         SingleUpnlSig memory upnlSig
244:     ) internal {
..SNIP..
249:         LibMuon.verifyPartyBUpnl(upnlSig, partyB, partyA);
250:         int256 availableBalance = LibAccount.partyBAvailableBalanceForLiquidation(
251:             upnlSig.upnl,
252:             partyB,
253:             partyA
254:         );
..SNIP..
```

However, after using an unrealized profit and loss (uPnL) signature (`upnlSig`), it does not increment the nonce at the end of the function. As a result, the same unrealized profit and loss (uPnL) signature (`upnlSig`) can be reused in other functions that accept an unrealized profit and loss (uPnL) signature (`upnlSig`).

The unrealized profit and loss (uPnL) signature (`upnlSig`) of `liquidatePartyA` function can be re-used in the following functions:

- `AccountFacet.deallocate`

The unrealized profit and loss (uPnL) signature (`upnlSig`) of `liquidatePartyB` function can be re-used in the following functions:

- `AccountFacet.transferAllocation`
- `AccountFacet.deallocateForPartyB`
- `PartyBFacetImpl.lockQuote`

All four (4) functions above (`AccountFacet.deallocate`. `AccountFacet.transferAllocation`, `AccountFacet.deallocateForPartyB`, `PartyBFacetImpl.lockQuote`)  increment the nonce after using the signature. However, this was not done in the `LiquidationFacetImpl.liquidatePartyA` and `LiquidationFacetImpl.liquidatePartyB` functions.

## Impact

The same unrealized profit and loss (uPnL) signature (`upnlSig`) can be re-used and replayed across multiple functions. If the uPnL in an old signature gives an advantage (e.g. more profit) to the users compared to a newly generated signature, malicious users could cherry-pick and replay/submit the old signatures to the system. Since this is a zero-sum game, the gain of a user will be the loss of another user. The victim will end up losing more than expected.

In addition, once the first liquidation is completed, the signature can also be used to initiate the liquidation of the same party for a second time as long as the signature has not expired yet. If the liquidated party quickly injects funds and purchases more positions before the signature expires, the second liquidation might cause their new assets to be liquidated again.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L20

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L240

## Tool used

Manual Review

## Recommendation

Consider incrementing the nonce within the `liquidatePartyA` and `liquidatePartyB` so that the signature cannot be re-used or replayed.

```diff
function liquidatePartyA(address partyA, SingleUpnlSig memory upnlSig) internal {
    MAStorage.Layout storage maLayout = MAStorage.layout();

    LibMuon.verifyPartyAUpnl(upnlSig, partyA);
    int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
        upnlSig.upnl,
        partyA
    );
    require(availableBalance < 0, "LiquidationFacet: PartyA is solvent");
    maLayout.liquidationStatus[partyA] = true;
    maLayout.liquidationTimestamp[partyA] = upnlSig.timestamp;
    AccountStorage.layout().liquidators[partyA].push(msg.sender);
+   accountLayout.partyANonces[msg.sender] += 1;
}
```

```diff
function liquidatePartyB(
    address partyB,
    address partyA,
    SingleUpnlSig memory upnlSig
) internal {
    AccountStorage.Layout storage accountLayout = AccountStorage.layout();
    MAStorage.Layout storage maLayout = MAStorage.layout();
    QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();

    LibMuon.verifyPartyBUpnl(upnlSig, partyB, partyA);
    int256 availableBalance = LibAccount.partyBAvailableBalanceForLiquidation(
        upnlSig.upnl,
        partyB,
        partyA
    );
+	accountLayout.partyBNonces[partyB][partyA] += 1;
	..SNIP..
}
```