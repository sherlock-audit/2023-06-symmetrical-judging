xiaoming90

high

# Liquidation can be blocked by incrementing the nonce

## Summary

Malicious users could block liquidators from liquidating their accounts, which creates unfairness in the system and lead to a loss of profits to the counterparty.

## Vulnerability Detail

#### Instance 1 - Blocking liquidation of PartyA

A liquidatable PartyA can block liquidators from liquidating its account.

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

Within the `liquidatePartyA` function, it calls the `LibMuon.verifyPartyAUpnl` function.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibMuon.sol#L87

```solidity
File: LibMuon.sol
087:     function verifyPartyAUpnl(SingleUpnlSig memory upnlSig, address partyA) internal view {
088:         MuonStorage.Layout storage muonLayout = MuonStorage.layout();
089: //        require(
090: //            block.timestamp <= upnlSig.timestamp + muonLayout.upnlValidTime,
091: //            "LibMuon: Expired signature"
092: //        );
093:         bytes32 hash = keccak256(
094:             abi.encodePacked(
095:                 muonLayout.muonAppId,
096:                 upnlSig.reqId,
097:                 address(this),
098:                 partyA,
099:                 AccountStorage.layout().partyANonces[partyA],
100:                 upnlSig.upnl,
101:                 upnlSig.timestamp,
102:                 getChainId()
103:             )
104:         );
105:         verifyTSSAndGateway(hash, upnlSig.sigs, upnlSig.gatewaySignature);
106:     }
```

The `verifyPartyAUpnl` function will take the current nonce of PartyA (`AccountStorage.layout().partyANonces[partyA]`) to build the hash needed for verification.

When the PartyA becomes liquidatable or near to becoming liquidatable, it could start to monitor the mempool for any transaction that attempts to liquidate their accounts. Whenever a liquidator submits a `liquidatePartyA` transaction to liquidate their accounts, they could front-run it and submit a transaction to increment their nonce. When the liquidator's transaction is executed, the on-chain PartyA's nonce will differ from the nonce in the signature, and the liquidation transaction will revert.

For those chains that do not have a public mempool, they can possibly choose to submit a transaction that increments their nonce in every block as long as it is economically feasible to obtain the same result. 

Gas fees that PartyA spent might be cheap compared to the number of assets they will lose if their account is liquidated. Additionally, gas fees are cheap on L2 or side-chain (The protocol intended to support Arbitrum One, Arbitrum Nova, Fantom, Optimism, BNB chain, Polygon, Avalanche as per the contest details).

There are a number of methods for PartyA to increment their nonce, this includes but not limited to the following:

- Allocate or deallocate dust amount
- Lock and unlock the dummy position
- Calls `requestToClosePosition` followed by `requestToCancelCloseRequest` immediately

#### Instance 2 - Blocking liquidation of PartyB

The same exploit can be used to block the liquidation of PartyB since the `liquidatePartyB` function also relies on the `LibMuon.verifyPartyBUpnl,` which uses the on-chain nonce of PartyB for signature verification.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L240

```solidity
File: LiquidationFacetImpl.sol
240:     function liquidatePartyB(
..SNIP..
249:         LibMuon.verifyPartyBUpnl(upnlSig, partyB, partyA);
```

## Impact

PartyA can block their accounts from being liquidated by liquidators. With the ability to liquidate the insolvent PartyA, the unrealized profits of all PartyBs cannot be realized, and thus they will not be able to withdraw the profits.

PartyA could also exploit this issue to block their account from being liquidated to:

- Wait for their positions to recover to reduce their losses
- Buy time to obtain funds from elsewhere to inject into their accounts to bring the account back to a healthy level

Since this is a zero-sum game, the above-mentioned create unfairness to PartyB and reduce their profits.

The impact is the same for the blocking of PartyB liquidation.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L20

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L240

## Tool used

Manual Review

## Recommendation

In most protocols, whether an account is liquidatable is determined on-chain, and this issue will not surface. However, the architecture of Symmetrical protocol relies on off-chain and on-chain components to determine if an account is liquidatable, which can introduce a number of race conditions such as the one mentioned in this report. 

Consider reviewing the impact of malicious users attempting to increment the nonce in order to block certain actions in the protocols since most functions rely on the fact that the on-chain nonce must be in sync with the signature's nonce and update the architecture/contracts of the protocol accordingly.