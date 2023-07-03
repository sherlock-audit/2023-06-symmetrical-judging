rvierdiiev

medium

# AccountFacetImpl.allocate will not allow user to increase collateral, when he allocated balanceLimitPerUser amount and put it in position

## Summary
AccountFacetImpl.allocate will not allow user to increase collateral, when he allocated balanceLimitPerUser amount and put it in position.
## Vulnerability Detail
This issues describes edge case when user [allocated `balanceLimitPerUser` amount of funds](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L43-L47). And then open position that uses all or almost all of this funds. This is possible, because there is no check that will restrcit user to quote in such case.

Then it order to provide more collateral he will need to call `allocate`, but as he reached `balanceLimitPerUser` already, he will become liquidatable and can't provide more collateral.

Example
1.`balanceLimitPerUser` is 100000$.
2.user allocates this 100000$ and open position.
3.Now he can't provide more collateral
## Impact
User can't secure himself from being liquidatable.
## Code Snippet
Provided above
## Tool used

Manual Review

## Recommendation
I guess that you need to check that user's available balance will be at least 10%(for example) of `balanceLimitPerUser` in case if new quote will be open.