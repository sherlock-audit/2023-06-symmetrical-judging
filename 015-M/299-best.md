berndartmueller

medium

# Fee collector can grief the protocol by withdrawing trading fees that could still need to be returned to Party A

## Summary

The fee collector can grief the SYMM protocol by withdrawing the collected trading fees, resulting in an underflow error when attempting to return trading fees to Party A due to the lack of available funds.

## Vulnerability Detail

[Trading fees are collected](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L119) whenever Party A creates a new quote via the `sendQuote` function in the `PartyAFacetImpl` library. The accumulated fees are accounted for in the `accountLayout.balances[GlobalAppStorage.layout().feeCollector]` storage variable, the same `balances` mapping that is also used to account for the balances for Party A and Party B. The fee collector can withdraw the received trading fees at any time with the `deposit` function in the `AccountFacet` contract.

However, as trading fees are potentially returned to Party A, for example, when a quote gets canceled or expires, [deducting the returned trading fees](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L139) from the fee collector's balance can potentially revert with an underflow error if the balance is insufficient.

## Impact

If insufficient funds are available in the fee collector's balance (`accountLayout.balances[GlobalAppStorage.layout().feeCollector]`), attempting to return trading fees to Party A will revert with an underflow error. This will grief and DoS the following functions until the fee collector's balance is sufficiently replenished:

- `PartyAFacetImpl.requestToCancelQuote` in [line 136](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L136)
- `PartyAFacetImpl.forceCancelQuote` in [line 227](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L227)
- `PartyBFacetImpl.acceptCancelRequest` in [line 70](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L70)
- `PartyBFacetImpl.openPosition` in [line 231](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L231)
- `LibQuote.expireQuote` in [line 241](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L241)

## Code Snippet

[contracts/libraries/LibQuote.sol#L139](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L139)

```solidity
135: function returnTradingFee(uint256 quoteId) internal {
136:     AccountStorage.Layout storage accountLayout = AccountStorage.layout();
137:     uint256 tradingFee = LibQuote.getTradingFee(quoteId);
138:     accountLayout.allocatedBalances[QuoteStorage.layout().quotes[quoteId].partyA] += tradingFee;
139:     accountLayout.balances[GlobalAppStorage.layout().feeCollector] -= tradingFee; // @audit-issue potentially reverts with an underflow error
140: }
```

## Tool used

Manual Review

## Recommendation

Consider accounting the received trading fees in separate variables and keep track of the fees which can still be returned to Party A and only allow withdrawing the received fees that are non-returnable.
