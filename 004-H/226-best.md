xiaoming90

high

# Accounting error in PartyB's pending locked balance led to loss of funds

## Summary

Accounting error in the PartyB's pending locked balance during the partial filling of a position could lead to a loss of assets for PartyB.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacet.sol#L150

```solidity
File: PartyBFacetImpl.sol
112:     function openPosition(
113:         uint256 quoteId,
114:         uint256 filledAmount,
115:         uint256 openedPrice,
116:         PairUpnlAndPriceSig memory upnlSig
117:     ) internal returns (uint256 currentId) {
..SNIP..
155: 
156:         LibQuote.removeFromPendingQuotes(quote);
157: 
..SNIP..
225:             quoteLayout.quoteIdsOf[quote.partyA].push(currentId);
..SNIP..
237:             } else {
238:                 accountLayout.pendingLockedBalances[quote.partyA].sub(filledLockedValues);
239:                 accountLayout.partyBPendingLockedBalances[quote.partyB][quote.partyA].sub(
240:                     filledLockedValues
241:                 );
242:             }
```

| Parameter                  | Description                                                  |
| -------------------------- | ------------------------------------------------------------ |
| $quote_{current}$          | Current quote (Quote ID = 1)                                 |
| $quote_{new}$              | Newly created quote (Quote ID = 2) due to partially filling  |
| $lockedValue_{total}$      | 100 USD. The locked values of $quote_{current}$              |
| $lockedValue_{filled}$     | 30 USD. $lockedValue_{filled} = lockedValue_{total}\times\frac{filledAmount}{quote.quantity}$ |
| $lockedValue_{unfilled}$   | 70 USD. $lockedValue_{unfilled} = lockedValue_{total}-lockedValue_{filled}$ |
| $pendingLockedBalance_{a}$ | 100 USD. PartyA's pending locked balance                     |
| $pendingLockedBalance_{b}$ | 100 USD. PartyB's pending locked balance                     |
| $pendingQuotes_a$          | PartyA's pending quotes. $pendingQuotes_a = [quote_{current}]$ |
| $pendingQuotes_b$          | PartyB's pending quotes. $pendingQuotes_b = [quote_{current}]$ |

Assume the following states before the execution of the `openPosition` function:

- $pendingQuotes_a = [quote_{current}]$
- $pendingQuotes_b = [quote_{current}]$
- $pendingLockedBalance_{a} = 100\ USD$
- $pendingLockedBalance_{b} = 100\ USD$

When the `openPosition` function is executed, $quote_{current}$ will be removed from $pendingQuotes_a$ and $pendingQuotes_b$ in Line 156. 

If the position is partially filled, $quote_{current}$ will be filled, and $quote_{new}$ will be created with the unfilled amount ($lockedValue_{unfilled}$). The $quote_{new}$ is automatically added to PartyA's pending quote list in Line 225.

The states at this point are as follows:

- $pendingQuotes_a = [quote_{new}]$
- $pendingQuotes_b = []$
- $pendingLockedBalance_{a} = 100\ USD$
- $pendingLockedBalance_{b} = 100\ USD$

Line 238 removes the balance already filled ($lockedValue_{filled}$) from $pendingLockedBalance_{a}$ . The unfilled balance ($lockedValue_{unfilled}$) does not need to be removed from $pendingLockedBalance_{a}$ because it is now the balance of $quote_{new}$ that belong to PartyA. The value in $pendingLockedBalance_a$ is correct.

The states at this point are as follows:

- $pendingQuotes_a = [quote_{new}]$
- $pendingQuotes_b = []$
- $pendingLockedBalance_{a} = 70\ USD$
- $pendingLockedBalance_{b} = 100\ USD$

In Line 239, the code removes the balance already filled ($lockedValue_{filled}$) from $pendingLockedBalance_{b}$ 

The end state is as follows:

- $pendingQuotes_a = [quote_{new}]$
- $pendingQuotes_b = []$
- $pendingLockedBalance_{a} = 70\ USD$
- $pendingLockedBalance_{b} = 70\ USD$

As shown above, the value of $pendingLockedBalance_{b}$ is incorrect. Even though PartyB has no pending quote, 70 USD is still locked in the pending balance.

There are three (3) important points to note:

1) $quote_{current}$ has already been removed from $pendingQuotes_b$ in Line 156
2) $quote_{new}$ is not automatically added to $pendingQuotes_b$. When $quote_{new}$ is created, it is not automatically locked to PartyB.
3) $pendingQuotes_b$ is empty

As such, $lockedValue_{total}$ should be removed from the $pendingLockedBalance_{b}$ instead of only $lockedvalue_{filled}$.

## Impact

Every time PartyB partially fill a position, their $pendingLockedBalance_b$ will silently increase and become inflated. The pending locked balance plays a key role in the protocol's accounting system. Thus, an error in the accounting breaks many of the computations and invariants of the protocol.

For instance, it is used to compute the available balance of an account in `partyBAvailableForQuote` function. Assuming that the allocated balance remains the same. If the pending locked balance increases silently due to the bug, the available balance returned from the `partyBAvailableForQuote` function will decrease. Eventually, it will "consume" all the allocated balance, and there will be no available funds left for PartyB to open new positions or to deallocate+withdraw funds. Thus, leading to lost of assets for PartyB.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacet.sol#L150

## Tool used

Manual Review

## Recommendation

Update the affected function to remove $lockedValue_{total}$ from the $pendingLockedBalance_{b}$ instead of only $lockedvalue_{filled}$.

```diff
accountLayout.pendingLockedBalances[quote.partyA].sub(filledLockedValues);
accountLayout.partyBPendingLockedBalances[quote.partyB][quote.partyA].sub(
-    filledLockedValues
+    quote.lockedValues
);
```