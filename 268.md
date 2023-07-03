AkshaySrivastav

medium

# PartyB can deposit even when partyB deposits are paused

## Summary
All partyBs can deposit tokens even when `partyBActionsPaused` is set to true.

## Vulnerability Detail
Deposits of both partyA and partyB are stored in a common `balances` mapping.

The `AccountFacet.depositForPartyB` function has `whenNotPartyBActionsPaused` modifier which prevents the party deposits when partyB actions are paused.

```solidity
    function depositForPartyB(uint256 amount) external whenNotPartyBActionsPaused onlyPartyB {
        AccountFacetImpl.depositForPartyB(amount);
        emit DepositForPartyB(msg.sender, amount);
    }
```
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L93-L96

However this `whenNotPartyBActionsPaused` limitation can be bypassed by directly depositing using the `deposit` function.

## Impact
PartyB can deposit tokens even when the protocol wants to prevent them from depositing.

## Code Snippet
Provided above.

## Tool used

Manual Review

## Recommendation
Consider adding `notPartyB` modifier to the `deposit` function so that it cannot be used by partyB.
