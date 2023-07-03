xiaoming90

medium

# Cooldown periods initialize to 95129375 Years

## Summary

The cooldown periods are initialized to 95129375 years, which could prevent `forceCancelQuote`, `forceCancelCloseRequest`, and `forceClosePosition` functions from working if they were not updated later.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L17

```solidity
File: ControlFacet.sol
17:     function init(address user, address collateral, address feeCollector) external onlyOwner {
18:         MAStorage.Layout storage maLayout = MAStorage.layout();
19:         GlobalAppStorage.Layout storage appLayout = GlobalAppStorage.layout();
20: 
21:         appLayout.collateral = collateral;
22:         appLayout.balanceLimitPerUser = 500e18;
23:         appLayout.feeCollector = feeCollector;
24:         maLayout.deallocateCooldown = 300;
25:         maLayout.forceCancelCooldown = 3000000000000000; // @audit-info => 95129375 Years
26:         maLayout.forceCloseCooldown = 3000000000000000; // @audit-info => 95129375 Years
27:         maLayout.forceCancelCloseCooldown = 3000000000000000; // @audit-info => 95129375 Years
```

The force cooldowns are initialized to 95129375 years, which could prevent `forceCancelQuote`, `forceCancelCloseRequest`, and `forceClosePosition` functions from working if they were not updated later.

## Impact

If the force-related functions are not working, the user's assets might be locked within the protocols if the counterparty does not respond to the user's request.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L17

## Tool used

Manual Review

## Recommendation

Consider initializing the cooldown periods to a more reasonable value.