bin2chen

high

# LibMuon Signature hash collision

## Summary

In `LibMuon `, all signatures do not distinguish between type prefixes, and  `abi.encodePacked` is used when calculating the hash
Cause when  `abi.encodePacked`, if there is a dynamic array, different structures but the same hash value may be obtained
Due to conflicting hash values, signatures can be substituted for each other, making malicious use of illegal signatures possible

## Vulnerability Detail

The following two methods are examples

1.verifyPrices:
```solidity
    function verifyPrices(PriceSig memory priceSig, address partyA) internal view {
        MuonStorage.Layout storage muonLayout = MuonStorage.layout();
        require(priceSig.prices.length == priceSig.symbolIds.length, "LibMuon: Invalid length");
        bytes32 hash = keccak256(
            abi.encodePacked(
                muonLayout.muonAppId,
                priceSig.reqId,
                address(this),
@>              partyA,
@>              priceSig.upnl,
@>              priceSig.totalUnrealizedLoss,
@>              priceSig.symbolIds,
@>              priceSig.prices,
                priceSig.timestamp,
                getChainId()
            )
        );
        verifyTSSAndGateway(hash, priceSig.sigs, priceSig.gatewaySignature);
    }
```

2.verifyPartyAUpnlAndPrice
```solidity
    function verifyPartyAUpnlAndPrice(
        SingleUpnlAndPriceSig memory upnlSig,
        address partyA,
        uint256 symbolId
    ) internal view {
        MuonStorage.Layout storage muonLayout = MuonStorage.layout();
//        require(
//            block.timestamp <= upnlSig.timestamp + muonLayout.upnlValidTime,
//            "LibMuon: Expired signature"
//        );
        bytes32 hash = keccak256(
            abi.encodePacked(
                muonLayout.muonAppId,
                upnlSig.reqId,
                address(this),
@>              partyA,
@>              AccountStorage.layout().partyANonces[partyA],
@>              upnlSig.upnl,
@>              symbolId,
@>              upnlSig.price,
                upnlSig.timestamp,
                getChainId()
            )
        );
        verifyTSSAndGateway(hash, upnlSig.sigs, upnlSig.gatewaySignature);
    }
```
We exclude the same common part (muonAppId/reqId/address (this)/timestamp/getChainId ())

Through the following simplified test code, although the structure is different, the hash value is the same at that time

```solidity
  function test() external {
    address verifyPrices_partyA = address(0x1);
    int256 verifyPrices_upnl = 100;
    int256 verifyPrices_totalUnrealizedLoss = 100;
    uint256 [] memory verifyPrices_symbolIds = new uint256[](1);
    verifyPrices_symbolIds[0]=1;
    uint256 [] memory verifyPrices_prices = new uint256[](1);
    verifyPrices_prices[0]=1000;  

    bytes32 verifyPrices  = keccak256(abi.encodePacked(
            verifyPrices_partyA,
            verifyPrices_upnl,
            verifyPrices_totalUnrealizedLoss,
            verifyPrices_symbolIds,
            verifyPrices_prices
            ));

    address verifyPartyAUpnlAndPrice_partyA = verifyPrices_partyA;
    int256  verifyPartyAUpnlAndPrice_partyANonces = verifyPrices_upnl;
    int256  verifyPartyAUpnlAndPrice_upnl = verifyPrices_totalUnrealizedLoss;
    uint256 verifyPartyAUpnlAndPrice_symbolId = verifyPrices_symbolIds[0];
    uint256 verifyPartyAUpnlAndPrice_price = verifyPrices_prices[0];


    bytes32 verifyPartyAUpnlAndPrice  = keccak256(abi.encodePacked(
            verifyPartyAUpnlAndPrice_partyA,
            verifyPartyAUpnlAndPrice_partyANonces,
            verifyPartyAUpnlAndPrice_upnl,
            verifyPartyAUpnlAndPrice_symbolId,
            verifyPartyAUpnlAndPrice_price
            ));

    console.log("verifyPrices == verifyPartyAUpnlAndPrice:",verifyPrices == verifyPartyAUpnlAndPrice);

  }
```

```console
$ forge test -vvv

Running 1 test for test/Counter.t.sol:CounterTest
[PASS] test() (gas: 4991)
Logs:
  verifyPrices == verifyPartyAUpnlAndPrice: true

Test result: ok. 1 passed; 0 failed; finished in 11.27ms
```

From the above test example, we can see that the `verifyPrices` and `verifyPartyAUpnlAndPrice` signatures can be used interchangeably
If we get a legal `verifyPartyAUpnlAndPrice `, it can be used as the signature of `verifyPrices ()`
Use `partyANonces` as  `upnl`, etc

## Impact
Signatures can be reused due to hash collisions, through illegal signatures, using illegal `unpl`, etc

## Code Snippet
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibMuon.sol#L12

## Tool used

Manual Review

## Recommendation

It is recommended to add the prefix of the hash, or use `api.encode`
Such as:
```solidity
    function verifyPrices(PriceSig memory priceSig, address partyA) internal view {
        MuonStorage.Layout storage muonLayout = MuonStorage.layout();
        require(priceSig.prices.length == priceSig.symbolIds.length, "LibMuon: Invalid length");
        bytes32 hash = keccak256(
            abi.encodePacked(
+              "verifyPrices",
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

