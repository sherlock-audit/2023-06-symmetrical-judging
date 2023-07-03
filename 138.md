Ch_301

high

# Users could open multiple positions without locking any collateral

## Summary
To open a new position users should have enough funds (Free Allocation) to use as a collateral 

## Vulnerability Detail
In case the user has zero free allocation (all his allocations are locked) and he has a big profit so `upnl > 0`.

The users are able to keep opening new positions without locking any real collateral so they just will use their `upnl` (profit) (this part in [LibAccount.partyBAvailableForQuote()](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibAccount.sol#L88-L103) is the responsible of checking the available balance ) to bypass the check on [checkPartyBValidationToLockQuote()](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L88-L92)
Now the user locked the quote successfully. than he can invoke `openPosition()` to open it.

[LibSolvency.isSolventAfterOpenPosition()](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibSolvency.sol#L15-L97) will try to check again the `PartyB` available balance by sub-call to [LibAccount.partyBAvailableBalance()](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibAccount.sol#L118-L130) but this check is bypassed also.
It will just 
To summarize:  If `PartyB` all his allocations are locked and he has a big profit. he can open multiple positions without locking any collateral. If the majority of these positions get a profit he can repeat the process again 



Note:  This issue is also with all the similar functions
 
## Impact
- Users could open multiple positions without locking any collateral
- The protocol now is just printing money with ~zero risk for the users
## Code Snippet
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L83-L92

```solidity
        int256 availableBalance = LibAccount.partyBAvailableForQuote(
            upnl,
            msg.sender,
            quote.partyA
        );
        require(availableBalance >= 0, "PartyBFacet: Available balance is lower than zero");
        require(
            uint256(availableBalance) >= quote.lockedValues.total(),
            "PartyBFacet: insufficient available balance"
        );
```

## Tool used

Manual Review

## Recommendation
Use `upnl` only to check the liquidation