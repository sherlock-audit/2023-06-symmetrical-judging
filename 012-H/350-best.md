AkshaySrivastav

high

# `openPosition`: Insufficient validation on `openedPrice` input parameter

## Summary
The `openPosition` function lacks sufficient checks on `openedPrice` variable due to which an invalid value can be provided, resulting in DoS of operations.

## Vulnerability Detail
The validation in `openPosition` looks like this:
```solidity
        if (quote.positionType == PositionType.LONG) {
            require(
                openedPrice <= quote.requestedOpenPrice,
                "PartyBFacet: Opened price isn't valid"
            );
        } else {
            require(
                openedPrice >= quote.requestedOpenPrice,
                "PartyBFacet: Opened price isn't valid"
            );
        }
```
In case of short position, the partyB can provide uint256.max or uint256.max/2 value to this function. This value will get stored into `quote.openedPrice`.

Further this value is read throughout the protocol like in `LibSolvency.isSolventAfterOpenPosition`. If a huge value is set as the `openedPrice` then most arithmetic operations on this parameter will revert due to overflow/underflow error, causing a DoS of crucial protocol operations like liquidations.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibSolvency.sol#L15-L97

DoS in liquidations will result in loss of funds for the counter-parties of the positions.

## Impact
Discussed above

## Code Snippet

## Tool used

Manual Review

## Recommendation
Consider adding more strict input validation for the openedPrice parameter. For eg, the `openedPrice` should not deviate more than 20% from the `requestedOpenPrice`.