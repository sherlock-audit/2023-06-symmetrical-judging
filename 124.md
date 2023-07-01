bin2chen

medium

# lockQuote() increaseNonce parameters do not work properly

## Summary
in `lockQuote()` will execute `partyBNonces[quote.partyB][quote.partyA] += 1` if increaseNonce == true
But this operation is executed before setting `quote.partyB`, resulting in actually setting `partyBNonces[address(0)][quote.partyA] += 1`

## Vulnerability Detail
in `lockQuote()`  , when execute `partyBNonces[quote.partyB][quote.partyA] += 1` , `quote.paryB` is address(0)

```solidity
    function lockQuote(uint256 quoteId, SingleUpnlSig memory upnlSig, bool increaseNonce) internal {
        QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
        AccountStorage.Layout storage accountLayout = AccountStorage.layout();

        Quote storage quote = quoteLayout.quotes[quoteId];
        LibMuon.verifyPartyBUpnl(upnlSig, msg.sender, quote.partyA);
        checkPartyBValidationToLockQuote(quoteId, upnlSig.upnl);
        if (increaseNonce) {
@>          accountLayout.partyBNonces[quote.partyB][quote.partyA] += 1;
        }
        quote.modifyTimestamp = block.timestamp;
        quote.quoteStatus = QuoteStatus.LOCKED;
@>      quote.partyB = msg.sender;
        // lock funds for partyB
        accountLayout.partyBPendingLockedBalances[msg.sender][quote.partyA].addQuote(quote);
        quoteLayout.partyBPendingQuotes[msg.sender][quote.partyA].push(quote.id);
    }
```

actually setting `partyBNonces[address(0)][quote.partyA] += 1` 



## Impact

 increaseNonce parameters do not work properly

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L29-L38

## Tool used

Manual Review

## Recommendation
```solidity
    function lockQuote(uint256 quoteId, SingleUpnlSig memory upnlSig, bool increaseNonce) internal {
        QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
        AccountStorage.Layout storage accountLayout = AccountStorage.layout();

        Quote storage quote = quoteLayout.quotes[quoteId];
        LibMuon.verifyPartyBUpnl(upnlSig, msg.sender, quote.partyA);
        checkPartyBValidationToLockQuote(quoteId, upnlSig.upnl);
        if (increaseNonce) {
-           accountLayout.partyBNonces[quote.partyB][quote.partyA] += 1;
+           accountLayout.partyBNonces[msg.sender][quote.partyA] += 1;
        }
        quote.modifyTimestamp = block.timestamp;
        quote.quoteStatus = QuoteStatus.LOCKED;
        quote.partyB = msg.sender;
        // lock funds for partyB
        accountLayout.partyBPendingLockedBalances[msg.sender][quote.partyA].addQuote(quote);
        quoteLayout.partyBPendingQuotes[msg.sender][quote.partyA].push(quote.id);
    }
```