xiaoming90

high

# Funds stuck in pending balance as malicious PartyB can deny users from canceling their locked quotes

## Summary

Malicious PartyB denies users from canceling their locked quotes by repeatedly extending the force cancel quote cooldown. As a result, their funds will be stuck in the pending balance, which prevents them from deallocating and withdrawing these assets.

## Vulnerability Detail

When a user (PartyA) calls the `requestToCancelQuote` on a locked quote, the quote's status will be changed to `QuoteStatus.CANCEL_PENDING`. If PartyB does not accept the cancel request (`acceptCancelRequest`) within the cooldown period (`maLayout.forceCancelCooldown`), the user can forcefully cancel the quote by calling the `forceCancelQuote` function.

As long as the validation check at Line 216 is satisfied, the quote will be canceled. 

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L216

```solidity
File: PartyAFacetImpl.sol
209:     function forceCancelQuote(uint256 quoteId) internal {
..SNIP..
215:         require(
216:             block.timestamp > quote.modifyTimestamp + maLayout.forceCancelCooldown,
217:             "PartyAFacet: Cooldown not reached"
218:         );
```

However, malicious PartyB can keep extending the `quote.modifyTimestamp` so that PartyA would never have the chance to trigger the `forceCancelQuote` function. PartyB could bundle a transaction that calls `PartyBFacet.unlockQuote` function that is immediately followed by `PartyBFacet.lockQuote ` function to unlock and re-lock the same quote. This will update the `quote.modifyTimestamp` to the current `block.timestamp,` as shown in Line 32 below.

In addition, the malicious PartyB neither opens the existing locked position nor accepts the user's cancel quote request, which prevents the quote's status from moving to the `QuoteStatus.CANCELED` state.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L32

```solidity
File: PartyBFacetImpl.sol
22:     function lockQuote(uint256 quoteId, SingleUpnlSig memory upnlSig, bool increaseNonce) internal {
23:         QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
24:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
25: 
26:         Quote storage quote = quoteLayout.quotes[quoteId];
27:         LibMuon.verifyPartyBUpnl(upnlSig, msg.sender, quote.partyA);
28:         checkPartyBValidationToLockQuote(quoteId, upnlSig.upnl);
29:         if (increaseNonce) {
30:             accountLayout.partyBNonces[quote.partyB][quote.partyA] += 1;
31:         }
32:         quote.modifyTimestamp = block.timestamp;
```

Since the user (PartyA) cannot cancel its quote, their "usable" fund will always be locked in the pending balance.

Also, since the upper limit of pending quotes that a PartyA is finite (e.g. 15), another denial-of-service attack made possible with this exploit is that a malicious PartyB could lock as much as PartyA's pending quote as possible and choose not to unlock or open the position. This effectively left the victim (PartyA) with no or little to no quotes to open a new position.

## Impact

Malicious PartyB could grief the users by denying users from canceling their locked quotes. As a result, their funds will be stuck in the pending balance, which prevents them from deallocating and withdrawing these assets.

In addition, they cannot be redeployed those assets struck in the pending balance to more lucrative positions, resulting in a loss of potential gains.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L216

## Tool used

Manual Review

## Recommendation

The `quote.modifyTimestamp` is updated to the current timestamp in many functions, including the `lockQuote` function, as shown in the above example.  A quick search within the codebase shows that there are around 17 functions that update the `quote.modifyTimestamp` to the current timestamp when triggered. Each of these functions serves as a potential attack vector for malicious PartyB to extend the `quote.modifyTimestamp` and deny users from forcefully canceling their locked quotes.

It is recommended not to use the `quote.modifyTimestamp` for the purpose of determining if the force cancel quote cooldown has reached, as this variable has been used in many other places. Instead, consider creating a new variable, such as `quote.requestCancelQuoteTimestamp` solely for the purpose of computing the force cancel quote cooldown.

The following fixes will prevent malicious PartyB from extending the cooldown period since the `quote.requestCancelQuoteTimestamp` variable is only used solely for the purpose of determining if the force cancel quote cooldown has reached.

```diff
function requestToCancelQuote(uint256 quoteId) internal returns (QuoteStatus result) {
	..SNIP..
+	quote.requestCancelQuoteTimestamp = block.timestamp;
    quote.modifyTimestamp = block.timestamp;
}
```

```diff
function forceCancelQuote(uint256 quoteId) internal {
    AccountStorage.Layout storage accountLayout = AccountStorage.layout();
    MAStorage.Layout storage maLayout = MAStorage.layout();
    Quote storage quote = QuoteStorage.layout().quotes[quoteId];

    require(quote.quoteStatus == QuoteStatus.CANCEL_PENDING, "PartyAFacet: Invalid state");
    require(
-       block.timestamp > quote.modifyTimestamp + maLayout.forceCancelCooldown,
+		block.timestamp > quote.requestCancelQuoteTimestamp + maLayout.forceCancelCooldown,
        "PartyAFacet: Cooldown not reached"
    );
```