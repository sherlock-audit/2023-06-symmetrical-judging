xiaoming90

high

# Suspended PartyBs can bypass the withdrawal restriction by exploiting `fillCloseRequest`

## Summary

Suspended PartyBs can bypass the withdrawal restriction by exploiting `fillCloseRequest` function. Thus, an attacker can transfer the ill-gotten gains out of the protocol, leading to a loss of assets for the protocol and its users.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L26

```solidity
File: AccountFacet.sol
26:     function withdraw(uint256 amount) external whenNotAccountingPaused notSuspended(msg.sender) {
27:         AccountFacetImpl.withdraw(msg.sender, amount);
28:         emit Withdraw(msg.sender, msg.sender, amount);
29:     }
30: 
31:     function withdrawTo(
32:         address user,
33:         uint256 amount
34:     ) external whenNotAccountingPaused notSuspended(msg.sender) {
35:         AccountFacetImpl.withdraw(user, amount);
36:         emit Withdraw(msg.sender, user, amount);
37:     }
```

When a user is suspended, they are not allowed to call any of the withdraw functions (`withdraw` and `withdrawTo`) to withdraw funds from their account. These withdrawal functions are guarded by the `notSuspended` modifier that will revert if the user's address is suspended.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/utils/Accessibility.sol#L73

```solidity
File: Accessibility.sol
73:     modifier notSuspended(address user) {
74:         require(
75:             !AccountStorage.layout().suspendedAddresses[user],
76:             "Accessibility: Sender is Suspended"
77:         );
78:         _;
79:     }
```

However, suspected PartyBs can bypass this restriction by exploiting the `fillCloseRequest` function to transfer the assets out of the protocol. Following describe the proof-of-concept:

1) Anyone can be a PartyA within the protocol. Suspended PartyBs use one of their wallet addresses to operate as a PartyA. 
2) Use the PartyA to create a new position with an unfavorable price that will immediately result in a significant loss for any PartyB who takes on the position. The `partyBsWhiteList` of the new position is set to PartyB address only to prevent some other PartyB from taking on this position.
3) Once PartyB takes on the position, PartyB will immediately incur a significant loss, while PartyA will enjoy a significant gain due to the zero-sum nature of this game.
4) PartyA requested to close its position to lock the profits and PartyB will fill the close request.
5) PartyA calls the deallocate and withdraw functions to move the assets/gains out of the protocol.

## Impact

In the event of an attack, the protocol will suspend the malicious account and prevent it from transferring ill-gotten gains out of the protocol. However, since this restriction can be bypassed, the attacker can transfer the ill-gotten gains out of the protocol, leading to a loss of assets for the protocol and its users.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L98

## Tool used

Manual Review

## Recommendation

Add the `notSuspended` modifier to the `openPosition` and `fillCloseRequest` functions to block the above-described attack path.

```diff
function fillCloseRequest(
    uint256 quoteId,
    uint256 filledAmount,
    uint256 closedPrice,
    PairUpnlAndPriceSig memory upnlSig
- ) external whenNotPartyBActionsPaused onlyPartyBOfQuote(quoteId) notLiquidated(quoteId) {
+ ) external whenNotPartyBActionsPaused onlyPartyBOfQuote(quoteId) notLiquidated(quoteId) notSuspended(msg.sender) {
	..SNIP..
}
```

```diff
function openPosition(
    uint256 quoteId,
    uint256 filledAmount,
    uint256 openedPrice,
    PairUpnlAndPriceSig memory upnlSig
- ) external whenNotPartyBActionsPaused onlyPartyBOfQuote(quoteId) notLiquidated(quoteId) {
+ ) external whenNotPartyBActionsPaused onlyPartyBOfQuote(quoteId) notLiquidated(quoteId) notSuspended(msg.sender) {
    ..SNIP..
}
```