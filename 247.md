xiaoming90

medium

# `depositAndAllocateForPartyB` can be called against a liquidatable account

## Summary

Users might lose their funds if they use the `depositAndAllocateForPartyB` function to increase their allocated balance while their accounts have been marked as liquidatable.

## Vulnerability Detail

When liquidating PartyB, the account will be frozen once the `liquidatePartyB` function is executed, and the account's liquidation status will be set to `true` as shown in Line 272 below.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L272

```solidity
File: LiquidationFacetImpl.sol
240:     function liquidatePartyB(
241:         address partyB,
242:         address partyA,
243:         SingleUpnlSig memory upnlSig
244:     ) internal {
..SNIP..
272:         maLayout.partyBLiquidationStatus[partyB][partyA] = true;
273:         maLayout.partyBLiquidationTimestamp[partyB][partyA] = upnlSig.timestamp;
```

When a PartyB is marked as liquidatable, PartyB cannot deposit and allocate additional funds to their accounts. If PartyB attempts to do so, it will be denied by the `notLiquidatedPartyB` modifier on the `allocateForPartyB` function.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L66

```solidity
File: AccountFacet.sol
65:     // PartyB
66:     function allocateForPartyB(
67:         uint256 amount,
68:         address partyA
69:     ) public whenNotPartyBActionsPaused notLiquidatedPartyB(msg.sender, partyA) onlyPartyB {
70:         AccountFacetImpl.allocateForPartyB(amount, partyA, true);
71:         emit AllocateForPartyB(msg.sender, partyA, amount);
72:     }
```

Some users might use the convenient method called `depositAndAllocateForPartyB` to execute both deposit and allocate actions simultaneously. However, this function is not guarded by the `notLiquidatedPartyB` modifier. Thus, the users might call this function to increase their allocated balance while their accounts have been marked as liquidatable.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L74

```solidity
74:     function depositAndAllocateForPartyB(
75:         uint256 amount,
76:         address partyA
77:     ) external whenNotPartyBActionsPaused onlyPartyB {
78:         AccountFacetImpl.depositForPartyB(amount);
79:         AccountFacetImpl.allocateForPartyB(amount, partyA, true);
80:         emit DepositForPartyB(msg.sender, amount);
81:         emit AllocateForPartyB(msg.sender, partyA, amount);
82:     }
```

## Impact

If an account is marked as liquidatable, it is essentially considered frozen, and the users are not allowed to increase their allocated balance. Increasing the allocated balance of an account in this state would not help to bring the account back to a healthy threshold, even if a large sum of funds is injected into the account. 

When a user attempts to increase their allocated balance while their accounts have already been marked as liquidatable, there is a high possibility that the newly injected allocated balance will be lost as it will be used to pay the counterparty during liquidation.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L74

## Tool used

Manual Review

## Recommendation

Consider preventing users marked as liquidatable from calling the `depositAndAllocateForPartyB`. This measure has been implemented for all the other deposit and allocate related functions, except for the `depositAndAllocateForPartyB` function.

```diff
function depositAndAllocateForPartyB(
    uint256 amount,
    address partyA
- ) external whenNotPartyBActionsPaused onlyPartyB {
+ ) external whenNotPartyBActionsPaused notLiquidatedPartyB(msg.sender, partyA) onlyPartyB  {
    AccountFacetImpl.depositForPartyB(amount);
    AccountFacetImpl.allocateForPartyB(amount, partyA, true);
    emit DepositForPartyB(msg.sender, amount);
    emit AllocateForPartyB(msg.sender, partyA, amount);
}
```