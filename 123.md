rvierdiiev

medium

# In case if symbol is not valid it should be not possible to open position

## Summary
In case if symbol is not valid it should be not possible to open position
## Vulnerability Detail
When user creates a quote, then there is a check [that symbol is valid](In case if symbol is not active it should be not possible to open position). Otherwise, you can't create quote.

It's possible that after some time of trading, symbol [will be switched off](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L136-L144).

When this happened, then all trades that use old symbol should be closed in some time. And new trades should not be started. All pending qoutes should be canceled adn locked to be unlocked.
However, there is no check if symbol is valid in `PartyBFacetImpl.openPosition` function. As result partyB still can open position for not valid symbol.

It's possible that later, oracle will stop provide signatures with prices for that symbol, which means that position can be stucked.
## Impact
Possible to open position for invalid symbol.
## Code Snippet

## Tool used

Manual Review

## Recommendation
Do not allow to open position for invalid symbol.