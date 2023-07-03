xiaoming90

medium

# DOS attack due to lack of penalty for `unlock`

## Summary

Since there is no penalty for PartyB to lock and unlock a quote except for a temporary lock of their balance, this opens up an attack vector where a malicious PartyB could perform a denial-of-service (DOS) attack against PartyA, which negatively affects the protocol and its users.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L22

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
33:         quote.quoteStatus = QuoteStatus.LOCKED;
34:         quote.partyB = msg.sender;
35:         // lock funds for partyB
36:         accountLayout.partyBPendingLockedBalances[msg.sender][quote.partyA].addQuote(quote);
37:         quoteLayout.partyBPendingQuotes[msg.sender][quote.partyA].push(quote.id);
38:     }
```

Once a user issues a quote, any PartyB can secure it by calling the `lockQuote` function, which will bar other PartyBs from interacting with the quote.

For any given reason, PartyB, having secured the quote, can choose to abandon the opening position by calling the `unlockQuote` function

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L40

```solidity
File: PartyBFacetImpl.sol
40:     function unlockQuote(uint256 quoteId) internal returns (QuoteStatus) {
41:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
42: 
43:         Quote storage quote = QuoteStorage.layout().quotes[quoteId];
44:         require(quote.quoteStatus == QuoteStatus.LOCKED, "PartyBFacet: Invalid state");
45:         if (block.timestamp > quote.deadline) {
46:             QuoteStatus result = LibQuote.expireQuote(quoteId);
47:             return result;
48:         } else {
49:             accountLayout.partyBNonces[quote.partyB][quote.partyA] += 1;
50:             quote.modifyTimestamp = block.timestamp;
51:             quote.quoteStatus = QuoteStatus.PENDING;
52:             accountLayout.partyBPendingLockedBalances[quote.partyB][quote.partyA].subQuote(quote);
53:             LibQuote.removeFromPartyBPendingQuotes(quote);
54:             quote.partyB = address(0);
55:             return QuoteStatus.PENDING;
56:         }
57:     }
```

When a PartyB locks a quote, $x$ amount will be locked in its pending locked balance (`partyBPendingLockedBalances`). When the PartyB subsequently unlocks the quote, the same $x$ amount will be released from its pending locked balance.

Since there is no penalty for PartyB to lock and unlock a quote except for a temporary lock of their balance, this opens up an attack vector where a malicious PartyB could perform a denial-of-service (DOS) attack against PartyA. Whenever a PartyA creates a new quote, the malicious PartyB will step in and lock the quote but does not proceed to open the quote. PartyA could technically perform a force close against the locked quotes, but eventually, any new quotes created by the victim later will be locked by malicious PartyB too.

The whitelisting feature of the quote is not sufficient to guard against such an attack. If a PartyA wants its quote to be open for everyone for a valid reason, the PartyA cannot whitelist all the addresses in Ethereum except for the attacker address.

Since PartyA can only have a total of 15 pending quotes (`maLayout.pendingQuotesValidLength`) in their accounts, the victim will not be able to create new quotes if the attacker has locked all their existing quotes.

Another potential attack vector is that malicious PartyB could prevent other PartyBs from locking quotes. Whenever a PartyB attempt to lock a quote, the attacker would front-run them and lock the quote before them, and cause the victim's lock transaction to revert. The attacker will unlock the quote immediately after the attack to free up his pending locked balance.

## Impact

Affected PartyA will be unable to create new quotes, and their existing pending quotes will be locked by the attacker who does not intend to open the positions. PartyB, who genuinely wants to lock+open a quote, will be unable to do so. These lead to a loss of opportunity cost for the affected PartyA and PartyB. 

It also negatively affects the protocols as this issue could lead to fewer positions being opened, which in turn means less trading fee collected.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L22

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L40

## Tool used

Manual Review

## Recommendation

To prevent malicious PartyB from abusing the lock+unlock functions, consider imposing some penalty/fee if PartyB decides to unlock the quote. For instance, the penalty/fee can be computed as a percentage of the locked quote's value, and the collected penalty/fee can be forwarded to the PartyA and/or protocol.

This measure will prevent abuse and encourage PartyB to think carefully before locking any position. When a PartyB locks a position but does not open it, it leads to a loss of opportunity cost for the quote's PartyA because other PartyB would have opened the position, and they would have already started profiting from the position. As such, it is fair for PartyA to charge a fee from PartyB to compensate for their loss.