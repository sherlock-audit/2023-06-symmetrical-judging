xiaoming90

medium

# Malicious PartyB cannot be removed from the protocol

## Summary

It is not possible to remove a malicious PartyB completely from the system. In the event that a PartyB turns rogue and starts performing certain actions that harm the protocol or lead to the loss of assets, it might delay or complicate the recovery process or even be unable to stop the attack in the worst-case scenario.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L59

```solidity
File: ControlFacet.sol
59:     function registerPartyB(
60:         address partyB
61:     ) external onlyRole(LibAccessibility.PARTY_B_MANAGER_ROLE) {
62:         require(
63:             !MAStorage.layout().partyBStatus[partyB],
64:             "ControlFacet: Address is already registered"
65:         );
66:         MAStorage.layout().partyBStatus[partyB] = true;
67:         MAStorage.layout().partyBList.push(partyB);
68:         emit RegisterPartyB(partyB);
69:     }
```

To become a PartyB, the users must be registered by the protocol manager via `registerPartyB`. 

However, the protocol only has a method to register a PartyB, but does not have a method to de-register a PartyB

## Impact

In the event that a PartyB turns rogue and starts performing certain actions that harm the protocol or lead to the loss of assets, there is no way to remove the malicious PartyB from the system entirely. The protocol only has the option to suspend the malicious PartyB from calling the `withdraw` function, which might not be sufficient to guard against more sophisticated attacks.

To prove that it is insufficient, assume that the protocol suspends the malicious PartyB in an attempt to block them from calling the `withdraw` function. The attacker could exploit the issue I covered in another report to bypass this function by calling the `transferAllocation` function to transfer the assets to another account and use it to withdraw them. 

Even if the protocol has vetted PartyB at the time of registration, there is still a possibility that the private keys of PartyB be compromised by internal or external malicious actors later.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L59

## Tool used

Manual Review

## Recommendation

Consider implementing a new method to de-register PartyB. 

Following is the pseudo-code of the de-register method:

```solidity
function deregisterPartyB(
    address partyB
) external onlyRole(LibAccessibility.PARTY_B_MANAGER_ROLE) {
    require(
        MAStorage.layout().partyBStatus[partyB],
        "ControlFacet: Address is not registered"
    );
    MAStorage.layout().partyBStatus[partyB] = false;
    MAStorage.layout().partyBList.remove(partyB);
    emit DeregisterPartyB(partyB);
}
```
