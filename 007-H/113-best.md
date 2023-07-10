bin2chen

high

# setSymbolsPrice() can use the priceSig from a long time ago

## Summary
`setSymbolsPrice()` only restricts the maximum value of `priceSig.timestamp`, but not the minimum time
This allows a malicious user to choose a malicious `priceSig` from a long time ago
A malicious `priceSig.upnl` can seriously harm `partyB`

## Vulnerability Detail
`setSymbolsPrice()` only restricts the maximum value of `priceSig.timestamp`, but not the minimum time

```solidity
    function setSymbolsPrice(address partyA, PriceSig memory priceSig) internal {
        MAStorage.Layout storage maLayout = MAStorage.layout();
        AccountStorage.Layout storage accountLayout = AccountStorage.layout();
@>      LibMuon.verifyPrices(priceSig, partyA);
        require(
@>          priceSig.timestamp <=
                maLayout.liquidationTimestamp[partyA] + maLayout.liquidationTimeout,
            "LiquidationFacet: Expired signature"
        );
```
LibMuon.verifyPrices only check sign,  without check the time range
```solidity
    function verifyPrices(PriceSig memory priceSig, address partyA) internal view {
        MuonStorage.Layout storage muonLayout = MuonStorage.layout();
        require(priceSig.prices.length == priceSig.symbolIds.length, "LibMuon: Invalid length");
        bytes32 hash = keccak256(
            abi.encodePacked(
                muonLayout.muonAppId,
                priceSig.reqId,
                address(this),
                partyA,
                priceSig.upnl,
                priceSig.totalUnrealizedLoss,
                priceSig.symbolIds,
                priceSig.prices,
                priceSig.timestamp,
                getChainId()
            )
        );
        verifyTSSAndGateway(hash, priceSig.sigs, priceSig.gatewaySignature);
    }
```

In this case, a malicious user may pick any `priceSig` from a long time ago, and this `priceSig` may have a large negative `unpl`, leading to `LiquidationType.OVERDUE`, severely damaging `partyB`

We need to restrict `priceSig.timestamp` to be no smaller than `maLayout.liquidationTimestamp[partyA]` to avoid this problem

## Impact

Maliciously choosing the illegal `PriceSig` thus may hurt others user

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L34-L44

## Tool used

Manual Review

## Recommendation
 restrict `priceSig.timestamp` to be no smaller than `maLayout.liquidationTimestamp[partyA]`

```solidity
    function setSymbolsPrice(address partyA, PriceSig memory priceSig) internal {
        MAStorage.Layout storage maLayout = MAStorage.layout();
        AccountStorage.Layout storage accountLayout = AccountStorage.layout();

        LibMuon.verifyPrices(priceSig, partyA);
        require(maLayout.liquidationStatus[partyA], "LiquidationFacet: PartyA is solvent");
        require(
            priceSig.timestamp <=
                maLayout.liquidationTimestamp[partyA] + maLayout.liquidationTimeout,
            "LiquidationFacet: Expired signature"
        );
+     require(priceSig.timestamp >= maLayout.liquidationTimestamp[partyA],"invald price timestamp");
```
