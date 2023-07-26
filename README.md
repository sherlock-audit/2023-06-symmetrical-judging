# Issue H-1: setSymbolsPrice() can use the priceSig from a long time ago 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/113 

## Found by 
0xmuxyz, Ruhum, berndartmueller, bin2chen, cergyk, kutugu, libratus, mstpr-brainbot, nobody2018, pengun, rvierdiiev, shaka, simon135, sinarette, xiaoming90
## Summary
`setSymbolsPrice()` only restricts the maximum value of `priceSig.timestamp`, but not the minimum time
This allows a malicious user to choose a malicious `priceSig` from a long time ago
A malicious `priceSig.upnl` can seriously harm `partyB`

## Vulnerability Detail
`setSymbolsPrice()` only restricts the maximum value of `priceSig.timestamp`, but not the minimum time

```solidity
    function setSymbolsPrice(address partyA, PriceSig memory priceSig) internal {
        MAStorage.Layout storage maLayout = MAStorage.layout();
        AccountStorage.Layout storage accountLayout = AccountStorage.layout();
@>      LibMuon.verifyPrices(priceSig, partyA);
        require(
@>          priceSig.timestamp <=
                maLayout.liquidationTimestamp[partyA] + maLayout.liquidationTimeout,
            "LiquidationFacet: Expired signature"
        );
```
LibMuon.verifyPrices only check sign,  without check the time range
```solidity
    function verifyPrices(PriceSig memory priceSig, address partyA) internal view {
        MuonStorage.Layout storage muonLayout = MuonStorage.layout();
        require(priceSig.prices.length == priceSig.symbolIds.length, "LibMuon: Invalid length");
        bytes32 hash = keccak256(
            abi.encodePacked(
                muonLayout.muonAppId,
                priceSig.reqId,
                address(this),
                partyA,
                priceSig.upnl,
                priceSig.totalUnrealizedLoss,
                priceSig.symbolIds,
                priceSig.prices,
                priceSig.timestamp,
                getChainId()
            )
        );
        verifyTSSAndGateway(hash, priceSig.sigs, priceSig.gatewaySignature);
    }
```

In this case, a malicious user may pick any `priceSig` from a long time ago, and this `priceSig` may have a large negative `unpl`, leading to `LiquidationType.OVERDUE`, severely damaging `partyB`

We need to restrict `priceSig.timestamp` to be no smaller than `maLayout.liquidationTimestamp[partyA]` to avoid this problem

## Impact

Maliciously choosing the illegal `PriceSig` thus may hurt others user

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L34-L44

## Tool used

Manual Review

## Recommendation
 restrict `priceSig.timestamp` to be no smaller than `maLayout.liquidationTimestamp[partyA]`

```solidity
    function setSymbolsPrice(address partyA, PriceSig memory priceSig) internal {
        MAStorage.Layout storage maLayout = MAStorage.layout();
        AccountStorage.Layout storage accountLayout = AccountStorage.layout();

        LibMuon.verifyPrices(priceSig, partyA);
        require(maLayout.liquidationStatus[partyA], "LiquidationFacet: PartyA is solvent");
        require(
            priceSig.timestamp <=
                maLayout.liquidationTimestamp[partyA] + maLayout.liquidationTimeout,
            "LiquidationFacet: Expired signature"
        );
+     require(priceSig.timestamp >= maLayout.liquidationTimestamp[partyA],"invald price timestamp");
```

# Issue H-2: LibMuon Signature hash collision 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/214 

## Found by 
bin2chen, shaka
## Summary

In `LibMuon `, all signatures do not distinguish between type prefixes, and  `abi.encodePacked` is used when calculating the hash
Cause when  `abi.encodePacked`, if there is a dynamic array, different structures but the same hash value may be obtained
Due to conflicting hash values, signatures can be substituted for each other, making malicious use of illegal signatures possible

## Vulnerability Detail

The following two methods are examples

1.verifyPrices:
```solidity
    function verifyPrices(PriceSig memory priceSig, address partyA) internal view {
        MuonStorage.Layout storage muonLayout = MuonStorage.layout();
        require(priceSig.prices.length == priceSig.symbolIds.length, "LibMuon: Invalid length");
        bytes32 hash = keccak256(
            abi.encodePacked(
                muonLayout.muonAppId,
                priceSig.reqId,
                address(this),
@>              partyA,
@>              priceSig.upnl,
@>              priceSig.totalUnrealizedLoss,
@>              priceSig.symbolIds,
@>              priceSig.prices,
                priceSig.timestamp,
                getChainId()
            )
        );
        verifyTSSAndGateway(hash, priceSig.sigs, priceSig.gatewaySignature);
    }
```

2.verifyPartyAUpnlAndPrice
```solidity
    function verifyPartyAUpnlAndPrice(
        SingleUpnlAndPriceSig memory upnlSig,
        address partyA,
        uint256 symbolId
    ) internal view {
        MuonStorage.Layout storage muonLayout = MuonStorage.layout();
//        require(
//            block.timestamp <= upnlSig.timestamp + muonLayout.upnlValidTime,
//            "LibMuon: Expired signature"
//        );
        bytes32 hash = keccak256(
            abi.encodePacked(
                muonLayout.muonAppId,
                upnlSig.reqId,
                address(this),
@>              partyA,
@>              AccountStorage.layout().partyANonces[partyA],
@>              upnlSig.upnl,
@>              symbolId,
@>              upnlSig.price,
                upnlSig.timestamp,
                getChainId()
            )
        );
        verifyTSSAndGateway(hash, upnlSig.sigs, upnlSig.gatewaySignature);
    }
```
We exclude the same common part (muonAppId/reqId/address (this)/timestamp/getChainId ())

Through the following simplified test code, although the structure is different, the hash value is the same at that time

```solidity
  function test() external {
    address verifyPrices_partyA = address(0x1);
    int256 verifyPrices_upnl = 100;
    int256 verifyPrices_totalUnrealizedLoss = 100;
    uint256 [] memory verifyPrices_symbolIds = new uint256[](1);
    verifyPrices_symbolIds[0]=1;
    uint256 [] memory verifyPrices_prices = new uint256[](1);
    verifyPrices_prices[0]=1000;  

    bytes32 verifyPrices  = keccak256(abi.encodePacked(
            verifyPrices_partyA,
            verifyPrices_upnl,
            verifyPrices_totalUnrealizedLoss,
            verifyPrices_symbolIds,
            verifyPrices_prices
            ));

    address verifyPartyAUpnlAndPrice_partyA = verifyPrices_partyA;
    int256  verifyPartyAUpnlAndPrice_partyANonces = verifyPrices_upnl;
    int256  verifyPartyAUpnlAndPrice_upnl = verifyPrices_totalUnrealizedLoss;
    uint256 verifyPartyAUpnlAndPrice_symbolId = verifyPrices_symbolIds[0];
    uint256 verifyPartyAUpnlAndPrice_price = verifyPrices_prices[0];


    bytes32 verifyPartyAUpnlAndPrice  = keccak256(abi.encodePacked(
            verifyPartyAUpnlAndPrice_partyA,
            verifyPartyAUpnlAndPrice_partyANonces,
            verifyPartyAUpnlAndPrice_upnl,
            verifyPartyAUpnlAndPrice_symbolId,
            verifyPartyAUpnlAndPrice_price
            ));

    console.log("verifyPrices == verifyPartyAUpnlAndPrice:",verifyPrices == verifyPartyAUpnlAndPrice);

  }
```

```console
$ forge test -vvv

Running 1 test for test/Counter.t.sol:CounterTest
[PASS] test() (gas: 4991)
Logs:
  verifyPrices == verifyPartyAUpnlAndPrice: true

Test result: ok. 1 passed; 0 failed; finished in 11.27ms
```

From the above test example, we can see that the `verifyPrices` and `verifyPartyAUpnlAndPrice` signatures can be used interchangeably
If we get a legal `verifyPartyAUpnlAndPrice `, it can be used as the signature of `verifyPrices ()`
Use `partyANonces` as  `upnl`, etc

## Impact
Signatures can be reused due to hash collisions, through illegal signatures, using illegal `unpl`, etc

## Code Snippet
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibMuon.sol#L12

## Tool used

Manual Review

## Recommendation

It is recommended to add the prefix of the hash, or use `api.encode`
Such as:
```solidity
    function verifyPrices(PriceSig memory priceSig, address partyA) internal view {
        MuonStorage.Layout storage muonLayout = MuonStorage.layout();
        require(priceSig.prices.length == priceSig.symbolIds.length, "LibMuon: Invalid length");
        bytes32 hash = keccak256(
            abi.encodePacked(
+              "verifyPrices",
                muonLayout.muonAppId,
                priceSig.reqId,
                address(this),
                partyA,
                priceSig.upnl,
                priceSig.totalUnrealizedLoss,
                priceSig.symbolIds,
                priceSig.prices,
                priceSig.timestamp,
                getChainId()
            )
        );
        verifyTSSAndGateway(hash, priceSig.sigs, priceSig.gatewaySignature);
    }
```


# Issue H-3: `depositAndAllocateForPartyB` is broken due to incorrect precision 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/222 

## Found by 
0xChinedu, 0xmuxyz, AkshaySrivastav, Ch\_301, Juntao, PokemonAuditSimulator, berndartmueller, josephdara, kutugu, nobody2018, shaka, tvdung94, xiaoming90
## Summary

Due to incorrect precision, any users or external protocols utilizing the `depositAndAllocateForPartyB` to allocate 1000 USDC will end up only having 0.000000001 USDC allocated to their account. This might potentially lead to unexpected loss of funds due to the broken functionality if they rely on the accuracy of the function outcome to perform certain actions that deal with funds/assets.

## Vulnerability Detail

The input `amount` of the `depositForPartyB` function must be in native precision (e.g. USDC should be 6 decimals) as the function will automatically scale the amount to 18 precision in Lines 114-115 below.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L108

```solidity
File: AccountFacetImpl.sol
108:     function depositForPartyB(uint256 amount) internal {
109:         IERC20(GlobalAppStorage.layout().collateral).safeTransferFrom(
110:             msg.sender,
111:             address(this),
112:             amount
113:         );
114:         uint256 amountWith18Decimals = (amount * 1e18) /
115:         (10 ** IERC20Metadata(GlobalAppStorage.layout().collateral).decimals());
116:         AccountStorage.layout().balances[msg.sender] += amountWith18Decimals;
117:     }
```

On the other hand, the input `amount` of `allocateForPartyB` function must be in 18 decimals precision. Within the protocol, it uses 18 decimals for internal accounting.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L119

```solidity
File: AccountFacetImpl.sol
119:     function allocateForPartyB(uint256 amount, address partyA, bool increaseNonce) internal {
120:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
121: 
122:         require(accountLayout.balances[msg.sender] >= amount, "PartyBFacet: Insufficient balance");
123:         require(
124:             !MAStorage.layout().partyBLiquidationStatus[msg.sender][partyA],
125:             "PartyBFacet: PartyB isn't solvent"
126:         );
127:         if (increaseNonce) {
128:             accountLayout.partyBNonces[msg.sender][partyA] += 1;
129:         }
130:         accountLayout.balances[msg.sender] -= amount;
131:         accountLayout.partyBAllocatedBalances[msg.sender][partyA] += amount;
132:     }
```

The `depositAndAllocateForPartyB` function allows the users to deposit and allocate to their accounts within a single transaction. Within the function, it calls the `depositForPartyB` function followed by the `allocateForPartyB` function. The function passes the same `amount` into both the `depositForPartyB` and `allocateForPartyB` functions. However, the problem is that one accepts `amount` in native precision (e.g. 6 decimals) while the other accepts `amount` in scaled decimals (e.g. 18 decimals).

Assume that Alice calls the `depositAndAllocateForPartyB` function and intends to deposit and allocate 1000 USDC. Thus, she set the `amount` of the `depositAndAllocateForPartyB` function to `1000e6` as the precision of USDC is `6`.

The `depositForPartyB` function at Line 78 will work as intended because it will automatically be scaled up to internal accounting precision (18 decimals) within the function, and 1000 USDC will be deposited to her account.

The `allocateForPartyB` at Line 79 will not work as intended. The function expects the `amount` to be in internal accounting precision (18 decimals), but an `amount` in native precision (6 decimals for USDC) is passed in. As a result, only 0.000000001 USDC will be allocated to her account.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L74

```solidity
File: AccountFacet.sol
74:     function depositAndAllocateForPartyB(
75:         uint256 amount,
76:         address partyA
77:     ) external whenNotPartyBActionsPaused onlyPartyB {
78:         AccountFacetImpl.depositForPartyB(amount);
79:         AccountFacetImpl.allocateForPartyB(amount, partyA, true);
80:         emit DepositForPartyB(msg.sender, amount);
81:         emit AllocateForPartyB(msg.sender, partyA, amount);
82:     }
```

## Impact

Any users or external protocols utilizing the `depositAndAllocateForPartyB` to allocate 1000 USDC will end up only having 0.000000001 USDC allocated to their account, which might potentially lead to unexpected loss of funds due to the broken functionality if they rely on the accuracy of the outcome to perform certain actions dealing with funds/assets.

For instance, Bob's account is close to being liquidated. Thus, he might call the `depositAndAllocateForPartyB` function in an attempt to increase its allocated balance and improve its account health level to avoid being liquidated. However, the `depositAndAllocateForPartyB` is not working as expected, and its allocated balance only increased by a very small amount (e.g. 0.000000001 USDC in our example). Bob believed that his account was healthy, but in reality, his account was still in danger as it only increased by 0.000000001 USDC. In the next one or two blocks, the price swung, and Bob's account was liquidated.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L74

## Tool used

Manual Review

## Recommendation

Scale the `amount` to internal accounting precision (18 decimals) before passing it to the `allocateForPartyB` function.

```diff
function depositAndAllocateForPartyB(
    uint256 amount,
    address partyA
) external whenNotPartyBActionsPaused onlyPartyB {
    AccountFacetImpl.depositForPartyB(amount);
+    uint256 amountWith18Decimals = (amount * 1e18) /
+    (10 ** IERC20Metadata(GlobalAppStorage.layout().collateral).decimals());
-    AccountFacetImpl.allocateForPartyB(amount, partyA, true);
+    AccountFacetImpl.allocateForPartyB(amountWith18Decimals, partyA, true);
    emit DepositForPartyB(msg.sender, amount);
    emit AllocateForPartyB(msg.sender, partyA, amount);
}
```

# Issue H-4: Accounting error in PartyB's pending locked balance led to loss of funds 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/226 

## Found by 
Ch\_301, Yuki, nican0r, xiaoming90
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



## Discussion

**MoonKnightDev**

In this scenario, only the pending locks of Party B would be incorrect, resulting in an accounting error for Party B. However, no funds would be stolen. so we don't consider it as "High"

**ctf-sec**

This issue does break accounting, recommend maintaining high severity here：

> For instance, it is used to compute the available balance of an account in partyBAvailableForQuote function. Assuming that the allocated balance remains the same. If the pending locked balance increases silently due to the bug, the available balance returned from the partyBAvailableForQuote function will decrease. Eventually, it will "consume" all the allocated balance, and there will be no available funds left for PartyB to open new positions or to deallocate+withdraw funds. Thus, leading to lost of assets for PartyB.

# Issue H-5: Unrealized profit and loss (uPnL) signature (`upnlSig`) can be re-used and replayed as nonce is not incremented 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/232 

## Found by 
bin2chen, cergyk, mstpr-brainbot, panprog, rvierdiiev, ver0759, xiaoming90
## Summary

The unrealized profit and loss (uPnL) signature (`upnlSig`) can be re-used and replayed as nonce is not incremented within the `LiquidationFacetImpl.liquidatePartyA` and `LiquidationFacetImpl.liquidatePartyB` functions.

## Vulnerability Detail

Both the `LiquidationFacetImpl.liquidatePartyA` and `LiquidationFacetImpl.liquidatePartyB` functions accept an unrealized profit and loss (uPnL) signature (`upnlSig`) and utilize it to compute the available balance of PartyA or PartyB

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L20

```solidity
File: LiquidationFacetImpl.sol
20:     function liquidatePartyA(address partyA, SingleUpnlSig memory upnlSig) internal {
21:         MAStorage.Layout storage maLayout = MAStorage.layout();
22: 
23:         LibMuon.verifyPartyAUpnl(upnlSig, partyA);
24:         int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
25:             upnlSig.upnl,
26:             partyA
27:         );
28:         require(availableBalance < 0, "LiquidationFacet: PartyA is solvent");
29:         maLayout.liquidationStatus[partyA] = true;
30:         maLayout.liquidationTimestamp[partyA] = upnlSig.timestamp;
31:         AccountStorage.layout().liquidators[partyA].push(msg.sender);
32:     }
```

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L240

```solidity
File: LiquidationFacetImpl.sol
240:     function liquidatePartyB(
241:         address partyB,
242:         address partyA,
243:         SingleUpnlSig memory upnlSig
244:     ) internal {
..SNIP..
249:         LibMuon.verifyPartyBUpnl(upnlSig, partyB, partyA);
250:         int256 availableBalance = LibAccount.partyBAvailableBalanceForLiquidation(
251:             upnlSig.upnl,
252:             partyB,
253:             partyA
254:         );
..SNIP..
```

However, after using an unrealized profit and loss (uPnL) signature (`upnlSig`), it does not increment the nonce at the end of the function. As a result, the same unrealized profit and loss (uPnL) signature (`upnlSig`) can be reused in other functions that accept an unrealized profit and loss (uPnL) signature (`upnlSig`).

The unrealized profit and loss (uPnL) signature (`upnlSig`) of `liquidatePartyA` function can be re-used in the following functions:

- `AccountFacet.deallocate`

The unrealized profit and loss (uPnL) signature (`upnlSig`) of `liquidatePartyB` function can be re-used in the following functions:

- `AccountFacet.transferAllocation`
- `AccountFacet.deallocateForPartyB`
- `PartyBFacetImpl.lockQuote`

All four (4) functions above (`AccountFacet.deallocate`. `AccountFacet.transferAllocation`, `AccountFacet.deallocateForPartyB`, `PartyBFacetImpl.lockQuote`)  increment the nonce after using the signature. However, this was not done in the `LiquidationFacetImpl.liquidatePartyA` and `LiquidationFacetImpl.liquidatePartyB` functions.

## Impact

The same unrealized profit and loss (uPnL) signature (`upnlSig`) can be re-used and replayed across multiple functions. If the uPnL in an old signature gives an advantage (e.g. more profit) to the users compared to a newly generated signature, malicious users could cherry-pick and replay/submit the old signatures to the system. Since this is a zero-sum game, the gain of a user will be the loss of another user. The victim will end up losing more than expected.

In addition, once the first liquidation is completed, the signature can also be used to initiate the liquidation of the same party for a second time as long as the signature has not expired yet. If the liquidated party quickly injects funds and purchases more positions before the signature expires, the second liquidation might cause their new assets to be liquidated again.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L20

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L240

## Tool used

Manual Review

## Recommendation

Consider incrementing the nonce within the `liquidatePartyA` and `liquidatePartyB` so that the signature cannot be re-used or replayed.

```diff
function liquidatePartyA(address partyA, SingleUpnlSig memory upnlSig) internal {
    MAStorage.Layout storage maLayout = MAStorage.layout();

    LibMuon.verifyPartyAUpnl(upnlSig, partyA);
    int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
        upnlSig.upnl,
        partyA
    );
    require(availableBalance < 0, "LiquidationFacet: PartyA is solvent");
    maLayout.liquidationStatus[partyA] = true;
    maLayout.liquidationTimestamp[partyA] = upnlSig.timestamp;
    AccountStorage.layout().liquidators[partyA].push(msg.sender);
+   accountLayout.partyANonces[msg.sender] += 1;
}
```

```diff
function liquidatePartyB(
    address partyB,
    address partyA,
    SingleUpnlSig memory upnlSig
) internal {
    AccountStorage.Layout storage accountLayout = AccountStorage.layout();
    MAStorage.Layout storage maLayout = MAStorage.layout();
    QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();

    LibMuon.verifyPartyBUpnl(upnlSig, partyB, partyA);
    int256 availableBalance = LibAccount.partyBAvailableBalanceForLiquidation(
        upnlSig.upnl,
        partyB,
        partyA
    );
+	accountLayout.partyBNonces[partyB][partyA] += 1;
	..SNIP..
}
```

# Issue H-6: Liquidation can be blocked by incrementing the nonce 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/233 

## Found by 
0xcrunch, AkshaySrivastav, Jiamin, Juntao, Ruhum, Yuki, berndartmueller, bin2chen, cergyk, circlelooper, mstpr-brainbot, nobody2018, p0wd3r, rvierdiiev, shaka, simon135, volodya, xiaoming90
## Summary

Malicious users could block liquidators from liquidating their accounts, which creates unfairness in the system and lead to a loss of profits to the counterparty.

## Vulnerability Detail

#### Instance 1 - Blocking liquidation of PartyA

A liquidatable PartyA can block liquidators from liquidating its account.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L20

```solidity
File: LiquidationFacetImpl.sol
20:     function liquidatePartyA(address partyA, SingleUpnlSig memory upnlSig) internal {
21:         MAStorage.Layout storage maLayout = MAStorage.layout();
22: 
23:         LibMuon.verifyPartyAUpnl(upnlSig, partyA);
24:         int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
25:             upnlSig.upnl,
26:             partyA
27:         );
28:         require(availableBalance < 0, "LiquidationFacet: PartyA is solvent");
29:         maLayout.liquidationStatus[partyA] = true;
30:         maLayout.liquidationTimestamp[partyA] = upnlSig.timestamp;
31:         AccountStorage.layout().liquidators[partyA].push(msg.sender);
32:     }
```

Within the `liquidatePartyA` function, it calls the `LibMuon.verifyPartyAUpnl` function.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibMuon.sol#L87

```solidity
File: LibMuon.sol
087:     function verifyPartyAUpnl(SingleUpnlSig memory upnlSig, address partyA) internal view {
088:         MuonStorage.Layout storage muonLayout = MuonStorage.layout();
089: //        require(
090: //            block.timestamp <= upnlSig.timestamp + muonLayout.upnlValidTime,
091: //            "LibMuon: Expired signature"
092: //        );
093:         bytes32 hash = keccak256(
094:             abi.encodePacked(
095:                 muonLayout.muonAppId,
096:                 upnlSig.reqId,
097:                 address(this),
098:                 partyA,
099:                 AccountStorage.layout().partyANonces[partyA],
100:                 upnlSig.upnl,
101:                 upnlSig.timestamp,
102:                 getChainId()
103:             )
104:         );
105:         verifyTSSAndGateway(hash, upnlSig.sigs, upnlSig.gatewaySignature);
106:     }
```

The `verifyPartyAUpnl` function will take the current nonce of PartyA (`AccountStorage.layout().partyANonces[partyA]`) to build the hash needed for verification.

When the PartyA becomes liquidatable or near to becoming liquidatable, it could start to monitor the mempool for any transaction that attempts to liquidate their accounts. Whenever a liquidator submits a `liquidatePartyA` transaction to liquidate their accounts, they could front-run it and submit a transaction to increment their nonce. When the liquidator's transaction is executed, the on-chain PartyA's nonce will differ from the nonce in the signature, and the liquidation transaction will revert.

For those chains that do not have a public mempool, they can possibly choose to submit a transaction that increments their nonce in every block as long as it is economically feasible to obtain the same result. 

Gas fees that PartyA spent might be cheap compared to the number of assets they will lose if their account is liquidated. Additionally, gas fees are cheap on L2 or side-chain (The protocol intended to support Arbitrum One, Arbitrum Nova, Fantom, Optimism, BNB chain, Polygon, Avalanche as per the contest details).

There are a number of methods for PartyA to increment their nonce, this includes but not limited to the following:

- Allocate or deallocate dust amount
- Lock and unlock the dummy position
- Calls `requestToClosePosition` followed by `requestToCancelCloseRequest` immediately

#### Instance 2 - Blocking liquidation of PartyB

The same exploit can be used to block the liquidation of PartyB since the `liquidatePartyB` function also relies on the `LibMuon.verifyPartyBUpnl,` which uses the on-chain nonce of PartyB for signature verification.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L240

```solidity
File: LiquidationFacetImpl.sol
240:     function liquidatePartyB(
..SNIP..
249:         LibMuon.verifyPartyBUpnl(upnlSig, partyB, partyA);
```

## Impact

PartyA can block their accounts from being liquidated by liquidators. With the ability to liquidate the insolvent PartyA, the unrealized profits of all PartyBs cannot be realized, and thus they will not be able to withdraw the profits.

PartyA could also exploit this issue to block their account from being liquidated to:

- Wait for their positions to recover to reduce their losses
- Buy time to obtain funds from elsewhere to inject into their accounts to bring the account back to a healthy level

Since this is a zero-sum game, the above-mentioned create unfairness to PartyB and reduce their profits.

The impact is the same for the blocking of PartyB liquidation.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L20

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L240

## Tool used

Manual Review

## Recommendation

In most protocols, whether an account is liquidatable is determined on-chain, and this issue will not surface. However, the architecture of Symmetrical protocol relies on off-chain and on-chain components to determine if an account is liquidatable, which can introduce a number of race conditions such as the one mentioned in this report. 

Consider reviewing the impact of malicious users attempting to increment the nonce in order to block certain actions in the protocols since most functions rely on the fact that the on-chain nonce must be in sync with the signature's nonce and update the architecture/contracts of the protocol accordingly.

# Issue H-7: Liquidation of PartyA will fail due to underflow errors 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/241 

## Found by 
bin2chen, cergyk, panprog, xiaoming90
## Summary

Liquidation of PartyA will fail due to underflow errors. As a result, assets will be stuck, and there will be a loss of assets for the counterparty (the creditor) since they cannot receive the liquidated assets.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L126

```solidity
File: LiquidationFacetImpl.sol
126:     function liquidatePositionsPartyA(
127:         address partyA,
128:         uint256[] memory quoteIds
129:     ) internal returns (bool) {
..SNIP..
152:             (bool hasMadeProfit, uint256 amount) = LibQuote.getValueOfQuoteForPartyA(
153:                 accountLayout.symbolsPrices[partyA][quote.symbolId].price,
154:                 LibQuote.quoteOpenAmount(quote),
155:                 quote
156:             );
..SNIP..
163:             if (
164:                 accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NORMAL
165:             ) {
166:                 accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += quote
167:                     .lockedValues
168:                     .cva;
169:                 if (hasMadeProfit) {
170:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;
171:                 } else {
172:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += amount;
173:                 }
174:             } else if (
175:                 accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.LATE
176:             ) {
177:                 accountLayout.partyBAllocatedBalances[quote.partyB][partyA] +=
178:                     quote.lockedValues.cva -
179:                     ((quote.lockedValues.cva * accountLayout.liquidationDetails[partyA].deficit) /
180:                         accountLayout.lockedBalances[partyA].cva);
181:                 if (hasMadeProfit) {
182:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;
183:                 } else {
184:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += amount;
185:                 }
186:             } else if (
187:                 accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.OVERDUE
188:             ) {
189:                 if (hasMadeProfit) {
190:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;
191:                 } else {
192:                     accountLayout.partyBAllocatedBalances[quote.partyB][partyA] +=
193:                         amount -
194:                         ((amount * accountLayout.liquidationDetails[partyA].deficit) /
195:                             uint256(-accountLayout.liquidationDetails[partyA].totalUnrealizedLoss));
196:                 }
197:             }
```

Assume that at this point, the allocated balance of PartyB (`accountLayout.partyBAllocatedBalances[quote.partyB][partyA]`) only has 1000 USD. 

In Line 152 above, the `getValueOfQuoteForPartyA` function is called to compute the PnL of a position. Assume the position has a huge profit of 3000 USD due to a sudden spike in price. For this particular position, PartyA will profit 3000 USD while PartyB will lose 3000 USD.

In this case, 3000 USD needs to be deducted from PartyB's account. However, when the `accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;` code at Line 170, 182, or 190 gets executed, an underflow error will occur, and the transaction will revert. This is because `partyBAllocatedBalances` is an unsigned integer, and PartyB only has 1000 USD of allocated balance, but the code attempts to deduct 3000 USD.

## Impact

Liquidation of PartyA will fail. Since liquidation cannot be completed, the assets that are liable to be liquidated cannot be transferred from PartyA (the debtor) to the counterparty (the creditor). Assets will be stuck, and there will be a loss of assets for the counterparty (the creditor) since they cannot receive the liquidated assets.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L126

## Tool used

Manual Review

## Recommendation

Consider implementing the following fixes to ensure that the amount to be deducted will never exceed the allocated balance of PartyB to prevent underflow errors from occurring.

```diff
if (hasMadeProfit) {
+	amountToDeduct = amount > accountLayout.partyBAllocatedBalances[quote.partyB][partyA] ? accountLayout.partyBAllocatedBalances[quote.partyB][partyA] : amount
+ 	accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amountToDeduct
-    accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;
} else {
    accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += amount;
}
```

# Issue M-1: underflows could occur in case deficit is bigger than totalUnrealizedLoss during OVERDUE liquidation at setSymbolsPrice 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/37 

## Found by 
0xGoodess
## Summary
underflows occurs in case deficit is bigger than totalUnrealizedLoss during OVERDUE liquidation at `setSymbolsPrice`
## Vulnerability Detail
During OVERDUE liquidation, `partyBAllocatedBalances[[quote.partyB][partyA]` would receive the lftover of the position, after deducing the deficit as a ratio of totalUnrealizedLoss. 

However if deficit is bigger than totalUnrealizedLoss, the subtraction would underflows
`amount -
                        ((amount * accountLayout.liquidationDetails[partyA].deficit) /
                            uint256(-accountLayout.liquidationDetails[partyA].totalUnrealizedLoss));`

```solidity
else if (
                accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.OVERDUE
            ) {
                if (hasMadeProfit) {
                    accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount;
                } else {
                    accountLayout.partyBAllocatedBalances[quote.partyB][partyA] +=
                        amount -
                        ((amount * accountLayout.liquidationDetails[partyA].deficit) /
                            uint256(-accountLayout.liquidationDetails[partyA].totalUnrealizedLoss));
                }
            }
```

calculation of deficit on OVERDUE liquidation
```solidity
else {
                uint256 deficit = uint256(-availableBalance) -
                    accountLayout.lockedBalances[partyA].lf -
                    accountLayout.lockedBalances[partyA].cva;
                accountLayout.liquidationDetails[partyA].liquidationType = LiquidationType.OVERDUE;
                accountLayout.liquidationDetails[partyA].deficit = deficit;
            }
            AccountStorage.layout().liquidators[partyA].push(msg.sender);
```
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L82-L88

Since `totalUnrealizedLoss` is passed by gateway, there is no bound over `deficit` would be less than totalUnrealizedLoss.

```solidity
        if (accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NONE) {
            accountLayout.liquidationDetails[partyA] = LiquidationDetail({
                liquidationType: LiquidationType.NONE,
                upnl: priceSig.upnl,
                totalUnrealizedLoss: priceSig.totalUnrealizedLoss,
                deficit: 0,
                liquidationFee: 0
            })
```
## Impact
OVERDUE liquidation reverts when deficit is bigger than totalUnrealizedLoss.

## Code Snippet
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L178-L180

## Tool used

Manual Review

## Recommendation
Consider putting a floor on deficit as `min(totalUnrealizedLoss, accountLayout.liquidationDetails[partyA].deficit)`

# Issue M-2: Liquidating pending quotes doesn't return trading fee to party A 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/71 

## Found by 
AkshaySrivastav, Ruhum, mstpr-brainbot, nobody2018, panprog, rvierdiiev, simon135, sinarette
## Summary
When a user is liquidated, the trading fees of the pending quotes aren't returned.

## Vulnerability Detail
When a pending/locked quote is canceled, the trading fee is sent back to party A, e.g.
- https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L136
- https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L227

But, when a pending quote is liquidated, the trading fee is not used for the liquidation. Instead, the fee collector keeps the funds:

```sol
    function liquidatePendingPositionsPartyA(address partyA) internal {
        QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
        require(
            MAStorage.layout().liquidationStatus[partyA],
            "LiquidationFacet: PartyA is solvent"
        );
        for (uint256 index = 0; index < quoteLayout.partyAPendingQuotes[partyA].length; index++) {
            Quote storage quote = quoteLayout.quotes[
                quoteLayout.partyAPendingQuotes[partyA][index]
            ];
            if (
                (quote.quoteStatus == QuoteStatus.LOCKED ||
                    quote.quoteStatus == QuoteStatus.CANCEL_PENDING) &&
                quoteLayout.partyBPendingQuotes[quote.partyB][partyA].length > 0
            ) {
                delete quoteLayout.partyBPendingQuotes[quote.partyB][partyA];
                AccountStorage
                .layout()
                .partyBPendingLockedBalances[quote.partyB][partyA].makeZero();
            }
            quote.quoteStatus = QuoteStatus.LIQUIDATED;
            quote.modifyTimestamp = block.timestamp;
        }
        AccountStorage.layout().pendingLockedBalances[partyA].makeZero();
        delete quoteLayout.partyAPendingQuotes[partyA];
    }
```

```sol
    function liquidatePartyB(
        address partyB,
        address partyA,
        SingleUpnlSig memory upnlSig
    ) internal {
        // ...
        uint256[] storage pendingQuotes = quoteLayout.partyAPendingQuotes[partyA];

        for (uint256 index = 0; index < pendingQuotes.length; ) {
            Quote storage quote = quoteLayout.quotes[pendingQuotes[index]];
            if (
                quote.partyB == partyB &&
                (quote.quoteStatus == QuoteStatus.LOCKED ||
                    quote.quoteStatus == QuoteStatus.CANCEL_PENDING)
            ) {
                accountLayout.pendingLockedBalances[partyA].subQuote(quote);

                pendingQuotes[index] = pendingQuotes[pendingQuotes.length - 1];
                pendingQuotes.pop();
                quote.quoteStatus = QuoteStatus.LIQUIDATED;
                quote.modifyTimestamp = block.timestamp;
            } else {
                index++;
            }
        }
```

These funds should be used to cover the liquidation. Since no trade has been executed, the fee collector shouldn't earn anything.

## Impact
Liquidation doesn't use paid trading fees to cover outstanding balances. Instead, the funds are kept by the fee collector.

## Code Snippet
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L105-L120
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L277-L293
## Tool used

Manual Review

## Recommendation
return the funds to party A. If party A is being liquidated, use the funds to cover the liquidation. Otherwise, party A keeps the funds.

# Issue M-3: In case if trading fee will be changed then refund will be done with wrong amount 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/92 

## Found by 
0xcrunch, Jiamin, circlelooper, nobody2018, rvierdiiev, xiaoming90
## Summary
In case if trading fee will be changed then refund will be done with wrong amount 
## Vulnerability Detail
When user creates quote, then he [pays trading fees](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L119). Amount that should be paid is calculated [inside `LibQuote.getTradingFee` function](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L144).

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L122-L133
```soldity
    function getTradingFee(uint256 quoteId) internal view returns (uint256 fee) {
        QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
        Quote storage quote = quoteLayout.quotes[quoteId];
        Symbol storage symbol = SymbolStorage.layout().symbols[quote.symbolId];
        if (quote.orderType == OrderType.LIMIT) {
            fee =
                (LibQuote.quoteOpenAmount(quote) * quote.requestedOpenPrice * symbol.tradingFee) /
                1e36;
        } else {
            fee = (LibQuote.quoteOpenAmount(quote) * quote.marketPrice * symbol.tradingFee) / 1e36;
        }
    }
```

As you can see `symbol.tradingFee` is used to determine fee amount. This fee [can be changed any time](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L164-L172).

When order is canceled, then [fee should be returned to user](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L136). This function also uses [`LibQuote.getTradingFee` function](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L137) to calculate fee to return.

So in case if order was created before fee changes, then returned amount will be not same, when it is canceled after fee changes.
## Impact
User or protocol losses portion of funds.
## Code Snippet
Provided above
## Tool used

Manual Review

## Recommendation
You can store fee paid by user inside quote struct. And when canceled return that amount.

# Issue M-4: In case if symbol is not valid it should be not possible to open position 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/122 

## Found by 
AkshaySrivastav, circlelooper, rvierdiiev
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

# Issue M-5: lockQuote() increaseNonce parameters do not work properly 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/123 

## Found by 
Juntao, Viktor\_Cortess, bin2chen, cergyk, kutugu, n1punp, nobody2018, rvierdiiev, xiaoming90
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



## Discussion

**MoonKnightDev**

The Party B can lock the quotes of only one Party A with a single signature and it cannot even open all of them. The sole repercussion would be the locking of the user's quotes. so we don't consider it as "High"

# Issue M-6: liquidatePositionsPartyB can be used by malicious liquidator to liquidate only select positions which artificially inflates partyA upnl and allows to steal funds 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/160 

## Found by 
panprog
## Summary

Liquidating partyB is a 2-step process. First, liquidator calls `liquidatePartyB`, and then `liquidatePositionsPartyB` can be called 1 or more times, each call with an array of quotes (positions) to liquidate, until all positions are liquidated. However, after the 1st step but before the 2nd step finishes - partyA can still do anything (like deallocating funds) with upnl calculations using positions between partyA and liquidated partyB (muon app doesn't check for liquidation of active position's parties, and smart contract code also ignores this).

Malicious liquidator can liquidate only positions which are in a loss for the partyA (keeping positions which are in a profit for the same partyA), temporarily artificially inflating upnl for this partyA. This allows partyA to deallocate max funds available, effectively stealing them. After the partyB liquidation process finishes and all positions are liquidated, partyA goes into a very high bad debt.

## Vulnerability Detail

`liquidatePartyB` sends all (or most of the) partyB's funds to partyA:

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L294-L296

`liquidatePositionsPartyB` can be called by any liquidator with an array of quotes, so liquidator chooses which positions he will liquidate and which positions will remain active:

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L331-L372

The liquidation process only finishes when all active partyB quotes/positions are liquidated, but until then, the first liquidator will have a choice of what quotes will remain active for a short time before next liquidator. During this time partyA will have incorrect upnl, because it will count some subset of positions, which can be chosen by liquidator.

While this bug mainly concerns muon app (which provides signed upnl for users), which is out of scope, the same logic flaw is also present in some parts of the smart contract code, such as closing positions. `requestToClosePosition` doesn't have any checks for either party liquidation status:

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L148-L191

`fillCloseRequest` doesn't have any checks for liquidation status either:

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L256-L293

There is also lack of liquidation check in the `liquidatePositionsPartyA`. This is the bug, which can be combined with this one to steal all protocol funds.

The following scenario is possible for malicious partyA to steal funds:

1. partyA opens LONG position with "good" partyB

2. At the same time, partyA opens 2 opposite (LONG and SHORT) positions with controlled partyB2 with minimally accepted allocated balance (with slightly different sizes, so that if price goes against partyA, partyB2 will be liquidatable)

3. When price goes against partyA (it has large loss in a position with partyB), partyB2 becomes liquidatable

4. partyA uses controlled liquidator to liquidate partyB2 and calls `liquidatePositionsPartyB` but only with `quoteId` of the LONG position (which is in a loss for partyA)

5. After that, partyA will have a very large profit from its SHORT position with partyB2, which will offset the loss from LONG position with partyB (LONG position with partyB2 is liquidated). partyA can deallocate it's full allocated balance, as the artificial unrealized profit allows to do this.

6. Any liquidator can finish liquidating partyB2, at this point partyA will go into bad debt, but since its allocated balance is 0, after partyA liquidation - partyB won't get anything and will lose all its profit. Effectively partyA has stolen funds from partyB.

It is also possible to just outright steal all funds from the protocol by using another bug (liquidation of partyA to inflate allocated balances of controlled partyB), but that's out of context of this bug.

## Impact

Any partyA which is in a loss on any of its position, can exploit the bug to temporarily inflate upnl and deallocate all funds at the expense of the other party, which won't get the profit from partyA positions due to bad debt.

Combining it with the other bug allows to steal all protocol funds.

## Code Snippet

Add this to any test, for example to `ClosePosition.behavior.ts`.

```ts
it("PartyA upnl boost off picky partyB position liquidation", async function () {
  const context: RunContext = this.context;

  this.user_allocated = decimal(1000);
  this.hedger_allocated = decimal(1000);
  this.hedger2_allocated = decimal(77);

  this.user = new User(this.context, this.context.signers.user);
  await this.user.setup();
  await this.user.setBalances(this.user_allocated, this.user_allocated, this.user_allocated);

  this.hedger = new Hedger(this.context, this.context.signers.hedger);
  await this.hedger.setup();
  await this.hedger.setBalances(this.hedger_allocated, this.hedger_allocated);

  this.hedger2 = new Hedger(this.context, this.context.signers.hedger2);
  await this.hedger2.setup();
  await this.hedger2.setBalances(this.hedger2_allocated, this.hedger2_allocated);

  this.liquidator = new User(this.context, this.context.signers.liquidator);
  await this.liquidator.setup();

  // open position (100 @ 10)
  await this.user.sendQuote(limitQuoteRequestBuilder().quantity(decimal(100)).price(decimal(10)).build());
  await this.hedger.lockQuote(1, 0, decimal(1));
  await this.hedger.openPosition(1, limitOpenRequestBuilder().filledAmount(decimal(100)).openPrice(decimal(10)).price(decimal(10)).build());

  // open 2 opposite direction positions with user-controlled hedger to exploit them later
  // (positions with slightly different sizes so that at some point the hedger can be liquidated)
  await this.user.sendQuote(limitQuoteRequestBuilder()
    .quantity(decimal(190))
    .price(decimal(10))
    .cva(decimal(10)).lf(decimal(5)).mm(decimal(10))
    .build()
  );
  await this.hedger2.lockQuote(2, 0, decimal(2, 16));
  await this.hedger2.openPosition(2, limitOpenRequestBuilder().filledAmount(decimal(90)).openPrice(decimal(10)).price(decimal(10)).build());

  await this.user.sendQuote(limitQuoteRequestBuilder()
    .positionType(PositionType.SHORT)
    .quantity(decimal(200))
    .price(decimal(10))
    .cva(decimal(10)).lf(decimal(5)).mm(decimal(10))
    .build()
  );
  await this.hedger2.lockQuote(3, 0, decimal(2, 16));
  await this.hedger2.openPosition(3, limitOpenRequestBuilder().filledAmount(decimal(100)).openPrice(decimal(10)).price(decimal(10)).build());

  var info = await this.user.getBalanceInfo();
  console.log("partyA allocated: " + info.allocatedBalances / 1e18 + " locked: " + info.totalLocked/1e18 + " pendingLocked: " + info.totalPendingLocked / 1e18);
  var info = await this.hedger2.getBalanceInfo(this.user.getAddress());
  console.log("partyB allocated: " + info.allocatedBalances / 1e18 + " locked: " + info.totalLocked/1e18 + " pendingLocked: " + info.totalPendingLocked / 1e18);

  // price goes to 5, so user is in a loss of -500, a slight profit of +50 from short position, but controlled hedger is in a -50 loss and 
  // becomes liquidatable
  // user now exploits the bug by liquidating controlled hedger
  await context.liquidationFacet.connect(this.liquidator.signer).liquidatePartyB(
    this.hedger2.signer.address,
    this.user.signer.address,
    await getDummySingleUpnlSig(decimal(-50)),
  );

  // liquidate only quote 2 (which is not profitable for the user)
  await context.liquidationFacet.connect(this.liquidator.signer).liquidatePositionsPartyB(
    this.hedger2.signer.address,
    this.user.signer.address,
    await getDummyQuotesPriceSig([2], [5]),
  )

  var liquidated = await context.viewFacet.isPartyBLiquidated(this.hedger2.signer.address, this.user.signer.address);
  console.log("PartyB Liquidated: " + liquidated);

  var info = await this.user.getBalanceInfo();
  console.log("partyA allocated: " + info.allocatedBalances / 1e18 + " locked: " + info.totalLocked/1e18 + " pendingLocked: " + info.totalPendingLocked / 1e18);

  var posCount = await this.context.viewFacet.partyAPositionsCount(this.user.getAddress());
  console.log("PartyA positions count: " + posCount);
  var openPositions = await this.context.viewFacet.getPartyAOpenPositions(
    this.user.getAddress(),
    0,
    posCount,
  );

  for (const pos of openPositions) {
    console.log("Position " + pos.id + ": type " + pos.positionType + ": " + pos.quantity/1e18 + " @ " + pos.openedPrice/1e18);
  }

  // deallocate max amount (upnl = -500 + 1000 = +500 for the user)
  // since we're in a profit, even after deallocating everything available we still have funds available, but can't deallocate more,
  // because allocated amount is already 0, and as it's unsigned, it can't go lower. This can be further exploited using another bug,
  // but that's out of this bug context
  await context.accountFacet.connect(this.user.signer).deallocate(decimal(1009), await getDummySingleUpnlSig(decimal(500)));

  // finish liquidation of user controlled hedger, forcing user in a big bad debt
  await context.liquidationFacet.connect(this.liquidator.signer).liquidatePositionsPartyB(
    this.hedger2.signer.address,
    this.user.signer.address,
    await getDummyQuotesPriceSig([3], [5]),
  )

  var info = await this.user.getBalanceInfo();
  console.log("partyA allocated: " + info.allocatedBalances / 1e18 + " locked: " + info.totalLocked/1e18 + " pendingLocked: " + info.totalPendingLocked / 1e18);

  var posCount = await this.context.viewFacet.partyAPositionsCount(this.user.getAddress());
  console.log("PartyA positions count: " + posCount);
  var openPositions = await this.context.viewFacet.getPartyAOpenPositions(
    this.user.getAddress(),
    0,
    posCount,
  );

  for (const pos of openPositions) {
    console.log("Position " + pos.id + ": type " + pos.positionType + ": " + pos.quantity/1e18 + " @ " + pos.openedPrice/1e18);
  }

});
```

## Tool used

Manual Review

## Recommendation

There are different ways to fix this vulnerability and it depends on what the team is willing to do. I'd say the safest fix will be to introduce some `temporarily locked` status for the partyA, and when any partyB is liquidated, connected partyA is put in this temporary status, which is lifted after liquidation finishes, so that the user can't do anything while in this status. However, this is a lot of work and possible room for more bugs.

Another way is to add liquidation check to muon app and when calculating unrealized profit/loss - ignore any positions for which either party is in liquidated status. And also fix the smart contract code to include this check as well (for example, it's possible to close position with liquidated partyB - there are no checks that partyB is not liquidated anywhere). This is the easier way, but might create problems in the future, if further features or protocols building on top won't take this problem into account.



## Discussion

**hrishibhat**

Considering this issue as medium since this requires malicious partyB and liquidator both which are whitelisted.


# Issue M-7: Some actions are allowed on partyB when corresponding partyA is liquidated allowing to steal all protocol funds 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/189 

## Found by 
panprog
## Summary

`deallocateForPartyB` function doesn't check if partyA is liquidated, allowing partyB to deallocate funds when partyA liquidation process is not finished:

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L84-L91

`transferAllocation` function doesn't check if partyA is liquidated either:

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L71-L106

Either of these functions allows to deallocate (or transfer, then deallocate) funds for partyB when partyA liquidation is not yet finished. Coupled with the ability for liquidator to choose which partyA positions to liquidate, this allows to steal all protocol funds.

## Vulnerability Detail

Liquidating partyA is a multi-step process. First, `liquidatePartyA` is called to mark the start of liquidation process. Then, liquidator has to set symbol prices, liquidate pending quotes and finally call `liquidatePositionsPartyA` (possibly multiple times) with liquidated positions. Each position, which is liquidated in the `liquidatePositionsPartyA` function increases `allocatedBalance` of partyB if the position is in a loss for partyA (profit for partyB).

The bug reported here allows for partyB to deallocate this increased `allocatedBalance` while partyA liquidation is still in process. The scenario to exploit this bug is as following:

1. User has to control partyA, partyB and liquidator.
2. Open 2 large opposite positions between partyA and partyB such that one of them is in a high loss and the other in the same/similar profit (easy to do via  openPrice which is far away from current market price, since both partyA and partyB are controlled by the same user).
3. Make partyA liquidatable (many ways to do this: for example, opposite positions can have slightly different size with minimal locked balances, so that when the price moves, this disparency can make partyA liquidatable)
4. Call `liquidatePartyA` and `setSymbolsPrice` (there is no bad debt, because 1 position is in a big loss, the other position in a big profit, but their sum is in a small loss, which is covered by allocatd balance)
5. Sign `singleUpnlSig` for partyB at this time (partyB is in a small profit)
6. User-controlled liquidator calls `liquidatePositionsPartyA` with id of only the position which is in a loss for partyA, profit for partyB. This call increases partyB allocated balance by a very high profit of the position. Moreover, this action doesn't change partyB's nonce, so previous partyB signature is still valid.
7. At this time partyB has large inflated allocatedBalance and the same big loss, however signature for when partyB was in a small profit is still valid, because party B nonce is the same (position liquidation didn't change it). Use that older signature to sign `deallocateForPartyB`, deallocating inflated balance (which can easily be higher than total protocol deposited funds).
8. Withdraw deallocated balance for partyB. At this point all protocol funds are stolen.

The other instances where there is no check if party is liquidated:

1. partyA `requestToClosePosition` (it checks if quote is liquidated, but doesn't check for neither partyA nor partyB liquidation status)
2. partyB `fillCloseRequest` (same as `requestToClosePosition`)
3. partyA `deallocate` checks for partyA liquidation status, but can't check for partyB liquidation status, because there can be multiple partyB's. This is reported as a separate bug, because the core problem (muon app signing incorrect upnl) and solution for that one is different.

## Impact

All protocol funds can be stolen if a user can control partyA, partyB and liquidator. Since partyB and liquidator roles are supposed to be easy to get, this means that most users are able to easily steal all protocol funds.

## Code Snippet

Add this to any test, for example to `ClosePosition.behavior.ts`.

```ts
import { getDummyPriceSig, getDummySingleUpnlAndPriceSig, getDummyQuotesPriceSig, getDummySingleUpnlSig } from "./utils/SignatureUtils";

it("Steal all funds via inflated PartyB allocated balance off picky partyA position liquidation", async function () {
  const context: RunContext = this.context;

  this.protocol_allocated = decimal(1000);

  this.user_allocated = decimal(590);
  this.hedger_allocated = decimal(420);

  // some unsuspecting user deposits 1000 into protocol (but doesn't allocate it)
  this.user2 = new User(this.context, this.context.signers.user);
  await this.user2.setup();
  await this.user2.setBalances(this.protocol_allocated, this.protocol_allocated, 0);

  // exploiter user controls partyA, partyB and liquidator
  this.user = new User(this.context, this.context.signers.user);
  await this.user.setup();
  await this.user.setBalances(this.user_allocated, this.user_allocated, this.user_allocated);

  this.hedger = new Hedger(this.context, this.context.signers.hedger);
  await this.hedger.setup();
  await this.hedger.setBalances(this.hedger_allocated, this.hedger_allocated);

  this.liquidator = new User(this.context, this.context.signers.liquidator);
  await this.liquidator.setup();

  // open 2 opposite direction positions with user-controlled hedger to exploit them later
  // (positions with slightly different sizes so that at some point the hedger can be liquidated)
  await this.user.sendQuote(limitQuoteRequestBuilder()
    .quantity(decimal(11000))
    .price(decimal(1))
    .cva(decimal(100)).lf(decimal(50)).mm(decimal(40))
    .build()
  );
  await this.hedger.lockQuote(1, 0, decimal(2, 16));
  await this.hedger.openPosition(1, limitOpenRequestBuilder().filledAmount(decimal(11000)).openPrice(decimal(1)).price(decimal(1)).build());

  await this.user.sendQuote(limitQuoteRequestBuilder()
    .positionType(PositionType.SHORT)
    .quantity(decimal(10000))
    .price(decimal(1))
    .cva(decimal(100)).lf(decimal(50)).mm(decimal(40))
    .build()
  );
  await this.hedger.lockQuote(2, 0, decimal(2, 16));
  await this.hedger.openPosition(2, limitOpenRequestBuilder().filledAmount(decimal(10000)).openPrice(decimal(1)).price(decimal(1)).build());

  var info = await this.user.getBalanceInfo();
  console.log("partyA allocated: " + info.allocatedBalances / 1e18 + " locked: " + info.totalLocked/1e18 + " pendingLocked: " + info.totalPendingLocked / 1e18);
  var info = await this.hedger.getBalanceInfo(this.user.getAddress());
  console.log("partyB allocated: " + info.allocatedBalances / 1e18 + " locked: " + info.totalLocked/1e18 + " pendingLocked: " + info.totalPendingLocked / 1e18);

  // price goes to 0.9, so partyA is in a loss of -100 and becomes liquidatable
  // user now exploits the bug by liquidating partyA
  await context.liquidationFacet.connect(this.liquidator.signer).liquidatePartyA(
    this.user.signer.address,
    await getDummySingleUpnlSig(decimal(-100)),
  );

  await context.liquidationFacet.connect(this.liquidator.signer).setSymbolsPrice(
      this.user.signer.address,
      await getDummyPriceSig([1], [decimal(9, 17)], decimal(-100), decimal(1100)),
    );

  // get partyB upnl signature before partyA position is liquidated (at which time partyB has upnl of +100)
  var previousSig = await getDummySingleUpnlSig(decimal(100));

  // liquidate only quote 1 (temporarily inflating balance of controlled partyB)
  await context.liquidationFacet.connect(this.liquidator.signer).liquidatePositionsPartyA(
    this.user.signer.address,
    [1]
  );

  var info = await this.hedger.getBalanceInfo(this.user.getAddress());
  console.log("after liquidation of partyA: partyB allocated: " + info.allocatedBalances / 1e18 + " locked: " + info.totalLocked/1e18 + " pendingLocked: " + info.totalPendingLocked / 1e18);

  // deallocate partyB with previous signature (before partyA's position is liquidated)
  // (current partyB upnl is -1100)
  await context.accountFacet.connect(this.hedger.signer).deallocateForPartyB(decimal(1530), this.user.getAddress(), previousSig);
  // alternatively use transferAllocation
  //await context.accountFacet.connect(this.hedger.signer).transferAllocation(decimal(1530), this.user.getAddress(), this.user2.getAddress(), previousSig);
  //await context.accountFacet.connect(this.hedger.signer).deallocateForPartyB(decimal(1530), this.user2.getAddress(), previousSig);

  var balance = await context.viewFacet.balanceOf(this.hedger.getAddress());
  console.log("PartyB balance to withdraw: " + balance/1e18);
  var info = await this.hedger.getBalanceInfo(this.user.getAddress());
  console.log("partyB allocated: " + info.allocatedBalances / 1e18 + " locked: " + info.totalLocked/1e18 + " pendingLocked: " + info.totalPendingLocked / 1e18);
  await time.increase(300);
  await context.accountFacet.connect(this.hedger.signer).withdraw(balance);

  var balance = await context.collateral.balanceOf(this.hedger.getAddress());
  console.log("Withdrawn partyB balance: " + balance/1e18);
  var balance = await context.collateral.balanceOf(context.diamond);
  console.log("Protocol balance: " + balance/1e18 + " (less than unsuspected user deposited)");

  // try to withdraw unsuspected user's balance
  await expect(context.accountFacet.connect(this.user2.signer).withdraw(this.protocol_allocated))
    .to.be.revertedWith("ERC20: transfer amount exceeds balance");

  console.log("User who only deposited 1000 is unable to withdraw his deposit because partyB has stolen his funds");

});
```

## Tool used

Manual Review

## Recommendation

Add require's (or modifiers) to check that neither partyA nor partyB of the quote are liquidated in the following functions:
1. `deallocateForPartyB`
2. `transferAllocation`
3. `requestToClosePosition`
4. `fillCloseRequest`



## Discussion

**ctf-sec**

Comment from senior watson:

Point 1 - As per the impact of the report, it mentioned the following:

All protocol funds can be stolen if a user can control partyA, partyB and liquidator. Since partyB and liquidator roles are supposed to be easy to get, this means that most users are able to easily steal all protocol funds.

The PartyB has to be vetted and whitelisted by protocol. The liquidator role also needs to be granted by the protocol. Only PartyA is public. It is challenging for an attacker to gain control of all three (3) roles in order to carry out the attack mentioned in the report. Thus, it does not meet the requirement of a high-risk rating

# Issue M-8: Malicious PartyB can block unfavorable close position requests causing a loss of profits for PartyB 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/224 

## Found by 
Yuki, berndartmueller, xiaoming90
## Summary

Malicious PartyB can block close position requests that are unfavorable toward them by intentionally choose not to fulfill the close request and continuously prolonging the force close position cooldown period, causing a loss of profits for PartyA.

## Vulnerability Detail

If PartyA invokes the `requestToClosePosition` function for an open quote, the quote's status will transition from `QuoteStatus.OPEN` to `QuoteStatus.CLOSE_PENDING`. In case PartyB fails to fulfill the close request (`fillCloseRequest`) during the cooldown period (`maLayout.forceCloseCooldown`), PartyA has the option to forcibly close the quote by utilizing the `forceClosePosition` function.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L261

```solidity
File: PartyAFacetImpl.sol
253:     function forceClosePosition(uint256 quoteId, PairUpnlAndPriceSig memory upnlSig) internal {
254:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
255:         MAStorage.Layout storage maLayout = MAStorage.layout();
256:         Quote storage quote = QuoteStorage.layout().quotes[quoteId];
257: 
258:         uint256 filledAmount = quote.quantityToClose;
259:         require(quote.quoteStatus == QuoteStatus.CLOSE_PENDING, "PartyAFacet: Invalid state");
260:         require(
261:             block.timestamp > quote.modifyTimestamp + maLayout.forceCloseCooldown,
262:             "PartyAFacet: Cooldown not reached"
263:         );
..SNIP..
```

Nevertheless, malicious PartyB can intentionally choose not to fulfill the close request and can continuously prolong the `quote.modifyTimestamp`, thereby preventing PartyA from ever being able to activate the `forceClosePosition` function.

Malicious PartyB could extend the `quote.modifyTimestamp` via the following steps:

1) Line 282 of the `fillCloseRequest` show that it is possible to partially fill a close request. As such, calls the `fillCloseRequest` function with the minimum possible `filledAmount` for the purpose of triggering the `LibQuote.closeQuote` function at Line 292.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L256

```solidity
File: PartyBFacetImpl.sol
256:     function fillCloseRequest(
257:         uint256 quoteId,
258:         uint256 filledAmount,
259:         uint256 closedPrice,
260:         PairUpnlAndPriceSig memory upnlSig
261:     ) internal {
..SNIP..
281:         if (quote.orderType == OrderType.LIMIT) {
282:             require(quote.quantityToClose >= filledAmount, "PartyBFacet: Invalid filledAmount");
283:         } else {
284:             require(quote.quantityToClose == filledAmount, "PartyBFacet: Invalid filledAmount");
285:         }
..SNIP..
292:         LibQuote.closeQuote(quote, filledAmount, closedPrice);
293:     }
```

2. Once the `LibQuote.closeQuote` function is triggered, Line 153 will update the `quote.modifyTimestamp` to the current timestamp, which effectively extends the cooldown period that PartyA has to wait before allowing to forcefully close the position.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L149

```solidity
File: LibQuote.sol
149:     function closeQuote(Quote storage quote, uint256 filledAmount, uint256 closedPrice) internal {
150:         QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
151:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
152: 
153:         quote.modifyTimestamp = block.timestamp;
..SNIP..
```

## Impact

PartyB has the ability to deny users from forcefully closing their positions by exploiting the issue. Malicious PartyB could abuse this by blocking PartyA from closing their positions against them when the price is unfavorable toward them. For instance, when PartyA is winning the game and decided to close some of its positions against PartyB, PartyB could block the close position request to deny PartyA of their profits and prevent themselves from losing the game.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L261

## Tool used

Manual Review

## Recommendation

The `quote.modifyTimestamp` is updated to the current timestamp in many functions, including the `closeQuote` function, as shown in the above example.  A quick search within the codebase shows that there are around 17 functions that update the `quote.modifyTimestamp` to the current timestamp when triggered. Each of these functions serves as a potential attack vector for malicious PartyB to extend the `quote.modifyTimestamp` and deny users from forcefully closing their positions

It is recommended not to use the `quote.modifyTimestamp` for the purpose of determining if the force close position cooldown has reached, as this variable has been used in many other places. Instead, consider creating a new variable, such as `quote.requestClosePositionTimestamp` solely for the purpose of computing the force cancel quote cooldown.

The following fixes will prevent malicious PartyB from extending the cooldown period since the `quote.requestClosePositionTimestamp` variable is only used solely for the purpose of determining if the force close position cooldown has reached.

```diff
function requestToClosePosition(
    uint256 quoteId,
    uint256 closePrice,
    uint256 quantityToClose,
    OrderType orderType,
    uint256 deadline,
    SingleUpnlAndPriceSig memory upnlSig
) internal {
..SNIP..
    accountLayout.partyANonces[quote.partyA] += 1;
    quote.modifyTimestamp = block.timestamp;
+	quote.requestCancelQuoteTimestamp = block.timestamp;
```

```diff
function forceClosePosition(uint256 quoteId, PairUpnlAndPriceSig memory upnlSig) internal {
    AccountStorage.Layout storage accountLayout = AccountStorage.layout();
    MAStorage.Layout storage maLayout = MAStorage.layout();
    Quote storage quote = QuoteStorage.layout().quotes[quoteId];

    uint256 filledAmount = quote.quantityToClose;
    require(quote.quoteStatus == QuoteStatus.CLOSE_PENDING, "PartyAFacet: Invalid state");
    require(
-       block.timestamp > quote.modifyTimestamp + maLayout.forceCloseCooldown,
+       block.timestamp > quote.requestCancelQuoteTimestamp + maLayout.forceCloseCooldown,
        "PartyAFacet: Cooldown not reached"
    );
```

In addition, review the `forceClosePosition` function and applied the same fix to it since it is vulnerable to the same issue, but with a different impact.




## Discussion

**hrishibhat**

@MoonKnightDev 

**hrishibhat**

Considering this a valid medium based on trust assumptions of partyB

# Issue M-9: Users might immediately be liquidated after position opening leading to a loss of CVA and Liquidation fee 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/225 

## Found by 
Ruhum, berndartmueller, cergyk, panprog, rvierdiiev, volodya, xiaoming90
## Summary

The insolvency check (`isSolventAfterOpenPosition`) within the `openPosition` function does not consider the locked balance adjustment, causing the user account to become insolvent immediately after the position is opened. As a result, the affected users will lose their CVA and liquidation fee locked in their accounts.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L150


```solidity
File: PartyBFacetImpl.sol
112:     function openPosition(
113:         uint256 quoteId,
114:         uint256 filledAmount,
115:         uint256 openedPrice,
116:         PairUpnlAndPriceSig memory upnlSig
117:     ) internal returns (uint256 currentId) {
..SNIP..
150:         LibSolvency.isSolventAfterOpenPosition(quoteId, filledAmount, upnlSig);
151: 
152:         accountLayout.partyANonces[quote.partyA] += 1;
153:         accountLayout.partyBNonces[quote.partyB][quote.partyA] += 1;
154:         quote.modifyTimestamp = block.timestamp;
155: 
156:         LibQuote.removeFromPendingQuotes(quote);
157: 
158:         if (quote.quantity == filledAmount) {
159:             accountLayout.pendingLockedBalances[quote.partyA].subQuote(quote);
160:             accountLayout.partyBPendingLockedBalances[quote.partyB][quote.partyA].subQuote(quote);
161: 
162:             if (quote.orderType == OrderType.LIMIT) {
163:                 quote.lockedValues.mul(openedPrice).div(quote.requestedOpenPrice);
164:             }
165:             accountLayout.lockedBalances[quote.partyA].addQuote(quote);
166:             accountLayout.partyBLockedBalances[quote.partyB][quote.partyA].addQuote(quote);
167:         }
```

The leverage of a position is computed based on the following formula.

$leverage = \frac{price \times quantity}{lockedValues.total()}$

When opening a position, there is a possibility that the leverage might change because the locked values and quantity are fixed, but it could get filled with a different market price compared to the one at the moment the user requested. Thus, the purpose of Line 163 above is to adjust the locked values to maintain a fixed leverage. After the adjustment, the locked value might be higher or lower.

The issue is that the insolvency check at Line 150 is performed before the adjustment is made. 

Assume that the adjustment in Line 163 cause the locked values to increase. The insolvency check (`isSolventAfterOpenPosition`) at Line 150 will be performed with old or unadjusted locked values that are smaller than expected. Since smaller locked values mean that there will be more available balance, this might cause the system to miscalculate that an account is not liquidatable, but in fact, it is actually liquidatable once the adjusted increased locked value is taken into consideration.

In this case, once the position is opened, the user account is immediately underwater and can be liquidated.

The issue will occur in the "complete fill" path and "partial fill" path since both paths adjust the locked values to maintain a fixed leverage. The "complete fill" path adjusts the locked values at [Line 185](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L185)

## Impact

Users might become liquidatable immediately after opening a position due to an incorrect insolvency check within the `openPosition`, which erroneously reports that the account will still be healthy after opening the position, while in reality, it is not. As a result, the affected users will lose their CVA and liquidation fee locked in their accounts.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L150

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L185

## Tool used

Manual Review

## Recommendation

Consider performing the insolvency check with the updated adjusted locked values.



## Discussion

**MoonKnightDev**

This scenario could only happen if the user requests to open a short position at a price significantly lower than the market value, creating conditions for potential liquidation. In this case, the identified bug would indeed facilitate this outcome. However, because the existence of such conditions is a prerequisite, we don't believe the severity level is high.

**ctf-sec**

Changed the severity to medium based on the comments above

# Issue M-10: Funds could be stolen via sandwich attack against symbol update transaction 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/227 

## Found by 
Juntao, libratus, mstpr-brainbot, xiaoming90
## Summary

Malicious users could perform a sandwich attack against the symbol update transaction to steal funds from the protocols

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L122

```solidity
File: LibQuote.sol
122:     function getTradingFee(uint256 quoteId) internal view returns (uint256 fee) {
123:         QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
124:         Quote storage quote = quoteLayout.quotes[quoteId];
125:         Symbol storage symbol = SymbolStorage.layout().symbols[quote.symbolId];
126:         if (quote.orderType == OrderType.LIMIT) {
127:             fee =
128:                 (LibQuote.quoteOpenAmount(quote) * quote.requestedOpenPrice * symbol.tradingFee) /
129:                 1e36;
130:         } else {
131:             fee = (LibQuote.quoteOpenAmount(quote) * quote.marketPrice * symbol.tradingFee) / 1e36;
132:         }
133:     }
134: 
135:     function returnTradingFee(uint256 quoteId) internal {
136:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
137:         uint256 tradingFee = LibQuote.getTradingFee(quoteId);
138:         accountLayout.allocatedBalances[QuoteStorage.layout().quotes[quoteId].partyA] += tradingFee;
139:         accountLayout.balances[GlobalAppStorage.layout().feeCollector] -= tradingFee;
140:     }
```

The amount of trading fee returned to the users is computed dynamically when the `returnTradingFee` function is triggered. In general, the following formula is used to compute the trading fee at any point in time. In the testing script, $TradingFeePercent$ is set to $1\%$.

$Trading Fee = Amount\times Price \times TradingFeePercent$

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L164

```solidity
File: ControlFacet.sol
164:     function setSymbolTradingFee(
165:         uint256 symbolId,
166:         uint256 tradingFee
167:     ) external onlyRole(LibAccessibility.SYMBOL_MANAGER_ROLE) {
168:         SymbolStorage.Layout storage symbolLayout = SymbolStorage.layout();
169:         require(symbolId >= 1 && symbolId <= symbolLayout.lastId, "ControlFacet: Invalid id");
170:         emit SetSymbolTradingFee(symbolId, symbolLayout.symbols[symbolId].tradingFee, tradingFee);
171:         symbolLayout.symbols[symbolId].tradingFee = tradingFee;
172:     }
```

The protocol manager can update the trading fee for a symbol via the `setSymbolTradingFee` function.

When the manager updates the trading for a symbol, a malicious user can perform a sandwich attack against the symbol update transaction to steal funds from the protocols. Following is the proof-of-concept for the attack:

1. Assume that the current `symbol.tradingFee` for `BTCUSDT` symbol is 1%.
2. The manager updates the `symbol.tradingFee` to 3% via the `setSymbolTradingFee` function and submits the symbol update transaction to the blockchain. The transaction appears in the mempool.
3. Bob saw the symbol update transaction in the mempool. He decided to front-run the symbol update transaction by submitting a new position/quote with the largest possible notional value allowed by the protocol. Let's assume he submits a position with a notional value of 1,000,000 USD. In this case, the trading fee will be 10,000 USD (1% of 1,000,000 USD).  
4. Bob also crafts another transaction that cancels the position/quote via the `requestToCancelQuote` function and has this transaction back-run the symbol update transaction.
5. When the create position/quote transaction is executed, 10,000 USD of the trading fee will be pulled from Bob's wallet address and locked in the protocol.
6. Next, the symbol update transaction will be executed, which will update the trading fee for `BTCUSDT` symbol from 1% to 3%
7. Finally, cancels the position/quote transaction will be executed. The trading fee returned is computed on the spot based on the latest trading fee of 3%. Thus, the trading fee returned will be 30,000 USD (3% of 1,000,000 USD)
8. Bob profits 20,000 USD (30,000 USD - 10,000 USD) within a single block.

## Impact

Funds could be stolen from the protocol.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L122

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L164

## Tool used

Manual Review

## Recommendation

Consider keeping track of how much trading fee was being paid in the first place when the position/quote was created. In this example, 10,000 USD of the trading fee is paid by Bob. Thus, the trading fee returned should not end up being more than what he originally paid (10,000 USD)



## Discussion

**MoonKnightDev**

When we are setting the symbol trading fee, we pause actions for party A. This ensures that no one can send a quote before this process, and we also verify that no quote is open prior to it.

**hrishibhat**

@xiaoming9090 Seems like an admin function call flow validation. 

**xiaoming9090**

@hrishibhat 
This issue does not require the admin to be malicious. A benign admin updates the trading fee, and an attacker can sandwich the admin's transaction to steal funds.

I agree that the process mentioned [here](https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/227#issuecomment-1640371263) by the sponsor will help to prevent this issue. However, this was not explicitly implemented within the `setSymbolTradingFee` function to check if PartyA's actions are paused before proceeding OR forcefully pause PartyA's actions before proceeding. Thus, it would be fair for the Watsons to raise this issue.
```typescript
File: ControlFacet.sol
    function setSymbolTradingFee(
        uint256 symbolId,
        uint256 tradingFee
    ) external onlyRole(LibAccessibility.SYMBOL_MANAGER_ROLE) {
        SymbolStorage.Layout storage symbolLayout = SymbolStorage.layout();
        require(symbolId >= 1 && symbolId <= symbolLayout.lastId, "ControlFacet: Invalid id");
        emit SetSymbolTradingFee(symbolId, symbolLayout.symbols[symbolId].tradingFee, tradingFee);
        symbolLayout.symbols[symbolId].tradingFee = tradingFee;
    }
```

**xiaoming9090**

@hrishibhat 
This issue does not require the admin to be malicious. A benign admin updates the trading fee, and an attacker can sandwich the admin's transaction to steal funds.

I agree that the process mentioned [here](https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/227#issuecomment-1640371263) by the sponsor will help to prevent this issue. However, this was not explicitly implemented within the `setSymbolTradingFee` function to check if PartyA's actions are paused. Thus, it would be fair for the Watsons to raise this issue.
```typescript
File: ControlFacet.sol
    function setSymbolTradingFee(
        uint256 symbolId,
        uint256 tradingFee
    ) external onlyRole(LibAccessibility.SYMBOL_MANAGER_ROLE) {
        SymbolStorage.Layout storage symbolLayout = SymbolStorage.layout();
        require(symbolId >= 1 && symbolId <= symbolLayout.lastId, "ControlFacet: Invalid id");
        emit SetSymbolTradingFee(symbolId, symbolLayout.symbols[symbolId].tradingFee, tradingFee);
        symbolLayout.symbols[symbolId].tradingFee = tradingFee;
    }
```

**ctf-sec**

Changed the severity to medium based on the conversation above

# Issue M-11: Suspended PartyBs can bypass the withdrawal restriction by exploiting `fillCloseRequest` 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/229 

## Found by 
0xcrunch, Juntao, PokemonAuditSimulator, Viktor\_Cortess, ast3ros, bin2chen, circlelooper, josephdara, mrpathfindr, mstpr-brainbot, panprog, rvierdiiev, xiaoming90
## Summary

Suspended PartyBs can bypass the withdrawal restriction by exploiting `fillCloseRequest` function. Thus, an attacker can transfer the ill-gotten gains out of the protocol, leading to a loss of assets for the protocol and its users.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L26

```solidity
File: AccountFacet.sol
26:     function withdraw(uint256 amount) external whenNotAccountingPaused notSuspended(msg.sender) {
27:         AccountFacetImpl.withdraw(msg.sender, amount);
28:         emit Withdraw(msg.sender, msg.sender, amount);
29:     }
30: 
31:     function withdrawTo(
32:         address user,
33:         uint256 amount
34:     ) external whenNotAccountingPaused notSuspended(msg.sender) {
35:         AccountFacetImpl.withdraw(user, amount);
36:         emit Withdraw(msg.sender, user, amount);
37:     }
```

When a user is suspended, they are not allowed to call any of the withdraw functions (`withdraw` and `withdrawTo`) to withdraw funds from their account. These withdrawal functions are guarded by the `notSuspended` modifier that will revert if the user's address is suspended.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/utils/Accessibility.sol#L73

```solidity
File: Accessibility.sol
73:     modifier notSuspended(address user) {
74:         require(
75:             !AccountStorage.layout().suspendedAddresses[user],
76:             "Accessibility: Sender is Suspended"
77:         );
78:         _;
79:     }
```

However, suspected PartyBs can bypass this restriction by exploiting the `fillCloseRequest` function to transfer the assets out of the protocol. Following describe the proof-of-concept:

1) Anyone can be a PartyA within the protocol. Suspended PartyBs use one of their wallet addresses to operate as a PartyA. 
2) Use the PartyA to create a new position with an unfavorable price that will immediately result in a significant loss for any PartyB who takes on the position. The `partyBsWhiteList` of the new position is set to PartyB address only to prevent some other PartyB from taking on this position.
3) Once PartyB takes on the position, PartyB will immediately incur a significant loss, while PartyA will enjoy a significant gain due to the zero-sum nature of this game.
4) PartyA requested to close its position to lock the profits and PartyB will fill the close request.
5) PartyA calls the deallocate and withdraw functions to move the assets/gains out of the protocol.

## Impact

In the event of an attack, the protocol will suspend the malicious account and prevent it from transferring ill-gotten gains out of the protocol. However, since this restriction can be bypassed, the attacker can transfer the ill-gotten gains out of the protocol, leading to a loss of assets for the protocol and its users.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L98

## Tool used

Manual Review

## Recommendation

Add the `notSuspended` modifier to the `openPosition` and `fillCloseRequest` functions to block the above-described attack path.

```diff
function fillCloseRequest(
    uint256 quoteId,
    uint256 filledAmount,
    uint256 closedPrice,
    PairUpnlAndPriceSig memory upnlSig
- ) external whenNotPartyBActionsPaused onlyPartyBOfQuote(quoteId) notLiquidated(quoteId) {
+ ) external whenNotPartyBActionsPaused onlyPartyBOfQuote(quoteId) notLiquidated(quoteId) notSuspended(msg.sender) {
	..SNIP..
}
```

```diff
function openPosition(
    uint256 quoteId,
    uint256 filledAmount,
    uint256 openedPrice,
    PairUpnlAndPriceSig memory upnlSig
- ) external whenNotPartyBActionsPaused onlyPartyBOfQuote(quoteId) notLiquidated(quoteId) {
+ ) external whenNotPartyBActionsPaused onlyPartyBOfQuote(quoteId) notLiquidated(quoteId) notSuspended(msg.sender) {
    ..SNIP..
}
```



## Discussion

**MoonKnightDev**

We disagree with the severity of this issue because, in the current system, Party B is permissioned. Therefore, it is highly unlikely that Party B will be suspended.

# Issue M-12: Imbalanced approach of distributing the liquidation fee within `setSymbolsPrice` function 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/231 

## Found by 
0xGoodess, PokemonAuditSimulator, Yuki, cergyk, kutugu, rvierdiiev, xiaoming90
## Summary

The imbalance approach of distributing the liquidation fee within `setSymbolsPrice` function could be exploited by malicious liquidators to obtain the liquidation fee without completing their tasks and maximizing their gains. While doing so, it causes harm or losses to other parties within the protocols.

## Vulnerability Detail

A PartyA can own a large number of different symbols in its portfolio. To avoid out-of-gas (OOG) errors from occurring during liquidation, the `setSymbolsPrice` function allows the liquidators to inject the price of the symbols in multiple transactions instead of all in one go.

Assume that the injection of the price symbols requires 5 transactions/rounds to complete and populate the price of all the symbols in a PartyA's portfolio. Based on the current implementation, only the first liquidator that calls the `setSymbolsPrice` will receive the liquidation fee. Liquidators that call the `setSymbolsPrice` function subsequently will not be added to the `AccountStorage.layout().liquidators[partyA]` listing as Line 88 will only be executed once when the `liquidationType` is still not initialized yet.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L34

```solidity
File: LiquidationFacetImpl.sol
34:     function setSymbolsPrice(address partyA, PriceSig memory priceSig) internal {
..SNIP..
56:         if (accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NONE) {
57:             accountLayout.liquidationDetails[partyA] = LiquidationDetail({
58:                 liquidationType: LiquidationType.NONE,
59:                 upnl: priceSig.upnl,
60:                 totalUnrealizedLoss: priceSig.totalUnrealizedLoss,
61:                 deficit: 0,
62:                 liquidationFee: 0
63:             });
..SNIP..
88:             AccountStorage.layout().liquidators[partyA].push(msg.sender);
89:         } else {
90:             require(
91:                 accountLayout.liquidationDetails[partyA].upnl == priceSig.upnl &&
92:                     accountLayout.liquidationDetails[partyA].totalUnrealizedLoss ==
93:                     priceSig.totalUnrealizedLoss,
94:                 "LiquidationFacet: Invalid upnl sig"
95:             );
96:         }
97:     }
```

A malicious liquidator could take advantage of this by only setting the symbol prices for the first round for each liquidation happening in the protocol. To maximize their profits, the malicious liquidator would call the `setSymbolsPrice` with none or only one (1) symbol price to save on the gas cost. The malicious liquidator would then leave it to the others to complete the rest of the liquidation process, and they will receive half of the liquidation fee at the end of the liquidation process.

Someone would eventually need to step in to complete the liquidation process. Even if none of the liquidators is incentivized to complete the process of setting the symbol prices since they will not receive any liquidation fee, the counterparty would eventually have no choice but to step in to perform the liquidation themselves. Otherwise, the profits of the counterparty cannot be realized. At the end of the day, the liquidation will be completed, and the malicious liquidator will still receive the liquidation fee.

## Impact

Malicious liquidators could exploit the liquidation process to obtain the liquidation fee without completing their tasks and maximizing their gains. While doing so, many liquidations would be stuck halfway since it is likely that no other liquidators will step in to complete the setting of the symbol prices because they will not receive any liquidation fee for doing so (not incentivized).

This could potentially lead to the loss of assets for various parties:

- The counterparty would eventually have no choice but to step in to perform the liquidation themselves. The counterparty has to pay for its own liquidation, even though it has already paid half the liquidation fee to the liquidator.
- Many liquidations would be stuck halfway, and liquidation might be delayed, which exposes users to greater market risks, including the risk of incurring larger losses or having to exit at an unfavorable price. 

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L34

## Tool used

Manual Review

## Recommendation

Consider a more balanced approach for distributing the liquidation fee for liquidators that calls the `setSymbolsPrice` function. For instance, the liquidators should be compensated based on the number of symbol prices they have injected. 

If there are 10 symbols to be filled up, if Bob filled up 4 out of 10 symbols, he should only receive 40% of the liquidation fee. This approach has already been implemented within the `liquidatePartyB` function via the `partyBPositionLiquidatorsShare` variable. Thus, the same design could be retrofitted into the `setSymbolsPrice` function.



## Discussion

**MoonKnightDev**

In the current system setup, we have established a role for liquidators. To give them this role, we might require an external contract in which they are obliged to lock a certain amount of money. This serves as a guarantee against any potential system sabotage or incomplete liquidation they may commit. If they fail to fulfill their role appropriately, they would face penalties.

**hrishibhat**

@xiaoming9090 Based on the above comment there are no restrictions applied on liquidators currently and there is the possibility of malicious actions by the liquidator, correct?

**hrishibhat**

Considering this issue as a valid medium, although the `liquidator role` is an external role and is restricted, it is still granted by the protocol. 

# Issue M-13: Liquidators will not be incentivized to liquidate certain PartyB accounts due to the lack of incentives 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/234 

## Found by 
Ruhum, berndartmueller, mstpr-brainbot, rvierdiiev, simon135, xiaoming90
## Summary

Liquidating certain accounts does not provide a liquidation fee to the liquidators. Liquidators will not be incentivized to liquidate such accounts, which may lead to liquidation being delayed or not performed, exposing Party B to unnecessary risks and potentially resulting in greater asset losses than anticipated.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L269

```solidity
File: LiquidationFacetImpl.sol
240:     function liquidatePartyB(
..SNIP..
259:         if (uint256(-availableBalance) < accountLayout.partyBLockedBalances[partyB][partyA].lf) {
260:             remainingLf =
261:                 accountLayout.partyBLockedBalances[partyB][partyA].lf -
262:                 uint256(-availableBalance);
263:             liquidatorShare = (remainingLf * maLayout.liquidatorShare) / 1e18;
264: 
265:             maLayout.partyBPositionLiquidatorsShare[partyB][partyA] =
266:                 (remainingLf - liquidatorShare) /
267:                 quoteLayout.partyBPositionsCount[partyB][partyA];
268:         } else {
269:             maLayout.partyBPositionLiquidatorsShare[partyB][partyA] = 0;
270:         }
```

Assume that the loss of Party B is more than the liquidation fee. In this case, the else branch of the above code within the `liquidatePartyB` function will be executed. The `liquidatorShare` and `partyBPositionLiquidatorsShare` variables will both be zero, which means the liquidators will get nothing in return for liquidating PartyBs

As a result, there will not be any incentive for the liquidators to liquidate such positions.

## Impact

Liquidators will not be incentivized to liquidate those accounts that do not provide them with a liquidation fee. As a result, the liquidation of those accounts might be delayed or not performed at all. When liquidation is not performed in a timely manner, PartyB ended up taking on additional unnecessary risks that could be avoided in the first place if a different liquidation incentive mechanism is adopted, potentially leading to PartyB losing more assets than expected.

Although PartyBs are incentivized to perform liquidation themselves since it is the PartyBs that take on the most risks from the late liquidation, the roles of PartyB and liquidator are clearly segregated in the protocol design. Only addresses granted the role of liquidators can perform liquidation as the liquidation functions are guarded by `onlyRole(LibAccessibility.LIQUIDATOR_ROLE)`. Unless the contracts are implemented in a manner that automatically grants a liquidator role to all new PartyB upon registration OR liquidation functions are made permissionless, PartyBs are likely not able to perform the liquidation themselves when the need arises.

Moreover, the PartyBs are not expected to be both a hedger and liquidator simultaneously as they might not have the skillset or resources to maintain an infrastructure for monitoring their accounts/positions for potential late liquidation.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L269

## Tool used

Manual Review

## Recommendation

Considering updating the liquidation incentive mechanism that will always provide some incentive for the liquidators to take the initiative to liquidate insolvent accounts. This will help to build a more robust and efficient liquidation mechanism for the protocols. One possible approach is to always give a percentage of the CVA of the liquidated account as a liquidation fee to the liquidators.



## Discussion

**MoonKnightDev**

If we encounter a late liquidation, our incentives are as follows:

If Party B or Party A, which is linked with only one counterparty, undergoes liquidation, and there is an isolated environment between the two, and in any case, all the funds transfer from one side to the other, so the liquidation time is not important anymore. And in a way, late liquidation is meaningless here.

Hence, one of the parties or any interested party can call this. If the individual being liquidated is connected with multiple counterparties, the remaining counterparties would call this liquidation to prevent further losses.

These can be called for when it is not beneficial for the liquidator.

But in general, we plan to always have incentives for liquidators

**hrishibhat**

@xiaoming9090 

**xiaoming9090**

> If we encounter a late liquidation, our incentives are as follows:
> 
> If Party B or Party A, which is linked with only one counterparty, undergoes liquidation, and there is an isolated environment between the two, and in any case, all the funds transfer from one side to the other, so the liquidation time is not important anymore. And in a way, late liquidation is meaningless here.
> 
> Hence, one of the parties or any interested party can call this. If the individual being liquidated is connected with multiple counterparties, the remaining counterparties would call this liquidation to prevent further losses.
> 
> These can be called for when it is not beneficial for the liquidator.
> 
> But in general, we plan to always have incentives for liquidators

In the second scenario where the liquidator does not perform the liquidation due to lack of incentives, the sponsor expects that the counterparty will call the liquidation themselves in order to prevent further losses. This seems reasonable on design, however, the implementation of current system does not allow the counterparty to do so.

As mentioned in my report and other Watson reports (https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/296), 

>Although PartyBs are incentivized to perform liquidation themselves since it is the PartyBs that take on the most risks from the late liquidation, the roles of PartyB and liquidator are clearly segregated in the protocol design. Only addresses granted the role of liquidators can perform liquidation as the liquidation functions are guarded by onlyRole(LibAccessibility.LIQUIDATOR_ROLE). Unless the contracts are implemented in a manner that automatically grants a liquidator role to all new PartyB upon registration OR liquidation functions are made permissionless, PartyBs are likely not able to perform the liquidation themselves when the need arises.

In short, the counterparty (PartyA or PartyB) could not perform the liquidation required as mentioned by the sponsor in the second scenario because they are not granted the role of liquidator by default. Thus, this issue is still valid.

**hrishibhat**

@MoonKnightDev 

# Issue M-14: `emergencyClosePosition` can be blocked 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/236 

## Found by 
nobody2018, rvierdiiev, xiaoming90
## Summary

The `emergencyClosePosition` function can be blocked as PartyA can change the position's status, which causes the transaction to revert when executed.

## Vulnerability Detail

Activating the emergency mode can be done either for a specific PartyB or for the entire system. Once activated, PartyB gains the ability to swiftly close positions without requiring users' requests. This functionality is specifically designed to cater to urgent situations where PartyBs must promptly close their positions.

Based on the `PartyBFacetImpl.emergencyClosePosition` function, a position can only be "emergency" close if its status is `QuoteStatus.OPENED`.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L312

```solidity
File: PartyBFacetImpl.sol
309:     function emergencyClosePosition(uint256 quoteId, PairUpnlAndPriceSig memory upnlSig) internal {
310:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
311:         Quote storage quote = QuoteStorage.layout().quotes[quoteId];
312:         require(quote.quoteStatus == QuoteStatus.OPENED, "PartyBFacet: Invalid state");
..SNIP..
```

As a result, if PartyA knows that emergency mode has been activated, PartyA could pre-emptively call the `PartyAFacetImpl.requestToClosePosition` with minimum possible `quantityToClose` (e.g. 1 wei) against their positions to change the state to `QuoteStatus.CLOSE_PENDING` so that the `PartyBFacetImpl.emergencyClosePosition` function will always revert when triggered by PartyB. This effectively blocks PartyB from "emergency" close the positions in urgent situations. 

PartyA could also block PartyB "emergency" close on-demand by front-running PartyB's `PartyBFacetImpl.emergencyClosePosition` transaction with the `PartyAFacetImpl.requestToClosePosition` with minimum possible `quantityToClose` (e.g. 1 wei) when detected.

PartyB could accept the close position request of 1 wei to revert the quote's status back to `QuoteStatus.OPENED` and try to perform an "emergency" close again. However, a sophisticated malicious user could front-run PartyA to revert the quote's status back to `QuoteStatus.CLOSE_PENDING` again to block the "emergency" close for a second time.

## Impact

During urgent situations where emergency mode is activated, the positions need to be promptly closed to avoid negative events that could potentially lead to serious loss of funds (e.g. the protocol is compromised, and the attacker is planning to or has started draining funds from the protocols). However, if the emergency closure of positions is blocked or delayed, it might lead to unrecoverable losses.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L312

## Tool used

Manual Review

## Recommendation

Update the `emergencyClosePosition` so that the "emergency" close can still proceed even if the position's status is `QuoteStatus.CLOSE_PENDING`.

```diff
function emergencyClosePosition(uint256 quoteId, PairUpnlAndPriceSig memory upnlSig) internal {
        AccountStorage.Layout storage accountLayout = AccountStorage.layout();
        Quote storage quote = QuoteStorage.layout().quotes[quoteId];
-		require(quote.quoteStatus == QuoteStatus.OPENED, "PartyBFacet: Invalid state");
+		require(quote.quoteStatus == QuoteStatus.OPENED || quote.quoteStatus == QuoteStatus.CLOSE_PENDING, "PartyBFacet: Invalid state");
..SNIP..
```



## Discussion

**MoonKnightDev**

Indeed, when Party B fulfills the close request, both Party A and Party B are required to obtain a new signature from Muon - Party A for the request to close and Party B for the emergency close. Party B is more likely to be successful. Moreover, Party A cannot front-run due to the distinct signatures. so we don't consider it as "High" 

# Issue M-15: Hedgers are not incentivized to respond to user's closing requests 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/239 

## Found by 
xiaoming90
## Summary

Hedgers could intentionally force the users to close the positions themselves via the `forceClosePosition` and charge a spread to earn more, which results in the users closing at a worse price, leading to a loss of profit for them.

## Vulnerability Detail

#### How `fillCloseRequest` function works?

For a Long position, when PartyB (Hedger) calls the `fillCloseRequest` function to fill a close position under normal circumstances, the hedger cannot charge a spread because the hedger has to close at the user's requested close price (`quote.requestedClosePrice`), 

If the hedger decides to close at a higher price, it is permissible by the function, but the hedger will lose more, and the users will gain more because the users' profit is computed based on `long profit = closing price - opening price`. 

Under normal circumstances, most users will set the requested close price (`quote.requestedClosePrice`) close to the market price most of the time.

In short, the `fillCloseRequest` function requires the hedger to match or exceed the user' requested price. The hedger cannot close at a price below the user's requested price in order to charge a spread.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L256

```solidity
function fillCloseRequest(
..SNIP..
    if (quote.positionType == PositionType.LONG) {
        require(
            closedPrice >= quote.requestedClosePrice,
            "PartyBFacet: Closed price isn't valid"
        )
```

#### How `forceClosePosition` function works?

For a Long position, the `forceCloseGapRatio` will allow the hedger to charge a spread from the user's requested price (`quote.requestedClosePrice`) when the user (PartyA) attempts to force close the position.

The `upnlSig.price` is the market price and `quote.requestedClosePrice` is the price users ask to close at. By having the `forceCloseGapRatio`, assuming that `forceCloseGapRatio` is 5%, this will create a spread between the two prices (`upnlSig.price` and `quote.requestedClosePrice`) that represent a cost that the users (PartyA) need to "pay" in order to force close a position.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L253

```solidity
function forceClosePosition(uint256 quoteId, PairUpnlAndPriceSig memory upnlSig) internal {
..SNIP..
    if (quote.positionType == PositionType.LONG) {
        require(
            upnlSig.price >=
                quote.requestedClosePrice +
                    (quote.requestedClosePrice * maLayout.forceCloseGapRatio) /
                    1e18,
            "PartyAFacet: Requested close price not reached"
        );
    ..SNIP..
    LibQuote.closeQuote(quote, filledAmount, quote.requestedClosePrice);
```

#### Issue with current design

Assume a hedger ignores the user's close request. In this case, the users (PartyA) have to call the `forceClosePosition` function by themselves to close the position and pay a spread.

The hedgers can abuse this mechanic to their benefit. Assuming the users (PartyA) ask to close a LONG position at a fair value, and the hedgers respond by calling the `fillCloseRequest` to close it. In this case, the hedgers won't be able to charge a spread because the hedgers are forced to close at a price equal to or higher than the user's asking closing price (`quote.requestedClosePrice`). 

However, if the hedger chooses to ignore the user's close request, this will force the user to call the `forceClosePosition,` and the user will have to pay a spread to the hedgers due to the gap ratio. In this case, the hedgers will benefit more due to the spread.

In the long run, the hedgers will be incentivized to ignore users' close requests.

## Impact

The hedgers will be incentivized to ignore users' close requests, resulting in the users having to wait for the cooldown before being able to force close a position themselves. The time spent waiting could potentially lead to a loss of opportunity cost for the users.

In addition, hedgers could intentionally force the users to close the positions themselves via the `forceClosePosition` and charge a spread to earn more, which results in the users closing at a worse price, leading to a loss of profit for them.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyA/PartyAFacetImpl.sol#L253

## Tool used

Manual Review

## Recommendation

Hedgers should not be entitled to charge a spread within the `forceClosePosition` function because some hedgers might intentionally choose not to respond to user requests in order to force the users to close the position themselves. In addition, hedgers are incentivized to force users to close the position themselves as the `forceClosePosition` function allows them the charge a spread.

Within the `forceClosePosition` function, consider removing the gap ratio to remove the spread and fill the position at the market price (`upnlSig.price`).

```diff
    function forceClosePosition(uint256 quoteId, PairUpnlAndPriceSig memory upnlSig) internal {
..SNIP..
        if (quote.positionType == PositionType.LONG) {
            require(
                upnlSig.price >=
+					quote.requestedClosePrice,                
-                   quote.requestedClosePrice +
-                        (quote.requestedClosePrice * maLayout.forceCloseGapRatio) /
-                        1e18,
                "PartyAFacet: Requested close price not reached"
            );
        } else {
            require(
                upnlSig.price <=
+               	quote.requestedClosePrice,
-                   quote.requestedClosePrice -
-                        (quote.requestedClosePrice * maLayout.forceCloseGapRatio) /
-                        1e18,
                "PartyAFacet: Requested close price not reached"
            );
        }
..SNIP..
-       LibQuote.closeQuote(quote, filledAmount, quote.requestedClosePrice);
+		LibQuote.closeQuote(quote, filledAmount, upnlSig.price);
    }
```

For long-term improvement to the protocol, assuming that the user's requested price is of fair value:

1) Hedger should be penalized for not responding to the user's closing request in a timely manner; OR
2) Hegder should be incentivized to respond to the user's closing request. For instance, they are entitled to charge a spread if they respond to user closing requests.

# Issue M-16: Rounding error when dividing liquidation fee 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/243 

## Found by 
xiaoming90
## Summary

Some amount of assets will be stuck in the contracts due to rounding errors.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L221

```solidity
File: LiquidationFacetImpl.sol
126:     function liquidatePositionsPartyA(
127:         address partyA,
128:         uint256[] memory quoteIds
129:     ) internal returns (bool) {
..SNIP..
220:             if (lf > 0) {
221:                 accountLayout.allocatedBalances[accountLayout.liquidators[partyA][0]] += lf / 2;
222:                 accountLayout.allocatedBalances[accountLayout.liquidators[partyA][1]] += lf / 2;
223:             }
```

At the end of the liquidation process for PartyA, the liquidation fee will be split into two and they are added to the balance of the liquidator(s) who triggered the `setSymbolsPrice` and `liquidatePositionsPartyA` functions.

If the liquidation fee (LF) is an odd value, dividing it by two will cause a round down. 

Assume that the LF is 9, then 9/2 = 4. 1 will be stuck in the contract.

## Impact

Some assets will be stuck in the contracts.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L221

## Tool used

Manual Review

## Recommendation

Consider sweeping the remaining amount to the last recipient as shown below.

```solidity
if (lf > 0) {
	uint payout = lf / 2
    accountLayout.allocatedBalances[accountLayout.liquidators[partyA][0]] += payout
    accountLayout.allocatedBalances[accountLayout.liquidators[partyA][1]] += (lf - payout)
} 
```

# Issue M-17: Rounding error causing assets to be stolen during withdrawal or lost during deposit 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/245 

## Found by 
xiaoming90
## Summary

Rounding errors could cause assets to be stolen during withdrawal or lost during deposit under certain conditions.

## Vulnerability Detail

#### Instance 1 - Token to be stolen during withdrawal

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L27

```solidity
File: AccountFacetImpl.sol
27:     function withdraw(address user, uint256 amount) internal {
28:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
29:         GlobalAppStorage.Layout storage appLayout = GlobalAppStorage.layout();
30:         require(
31:             block.timestamp >=
32:             accountLayout.withdrawCooldown[msg.sender] + MAStorage.layout().deallocateCooldown,
33:             "AccountFacet: Cooldown hasn't reached"
34:         );
35:         uint256 amountWith18Decimals = (amount * 1e18) /
36:         (10 ** IERC20Metadata(appLayout.collateral).decimals());
37:         accountLayout.balances[msg.sender] -= amountWith18Decimals;
38:         IERC20(appLayout.collateral).safeTransfer(user, amount);
39:     }
```

If the collateral changes to a token with more than 18 decimals in the future, users can drain assets from the contract.

If the collateral's decimals is larger than 18, it will be possible to specify a small `amount,` and the `amountWith18Decimals` will be rounded down to zero in Line 35-36 above. Then, in Line 37, nothing will be deducted from the account as `amountWith18Decimals` is zero.

In Line 38, the `amount`, which is non-zero, of collateral will be transferred to the users.

In summary, non-zero collateral is transferred to users, but nothing is deducted from the account balance. Repeat this process multiple times until all the collaterals in the contract are drained.

Based on the `setCollateral` function, it did not explicitly block collateral with decimals larger than 18. Thus, based on the current design and implementation, it is possible to introduce a collateral with decimals more than 18 in the future.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L95

```solidity
File: ControlFacet.sol
095:     function setCollateral(
096:         address collateral
097:     ) external onlyRole(LibAccessibility.DEFAULT_ADMIN_ROLE) {
098:         GlobalAppStorage.layout().collateral = collateral;
099:         emit SetCollateral(collateral);
100:     }
```

#### Instance 2 - Token to be lost during deposit

The similar issue will occur within the following functions, but with the opposite effect. The users deposit assets to the contract, but their account balance does not increase due to rounding errors.

- `AccountFacetImpl.deposit`
- `AccountFacetImpl.depositForPartyB`
- `AccountFacet.depositAndAllocate`

```solidity
File: AccountFacetImpl.sol
19:     function deposit(address user, uint256 amount) internal {
20:         GlobalAppStorage.Layout storage appLayout = GlobalAppStorage.layout();
21:         IERC20(appLayout.collateral).safeTransferFrom(msg.sender, address(this), amount);
22:         uint256 amountWith18Decimals = (amount * 1e18) /
23:         (10 ** IERC20Metadata(appLayout.collateral).decimals());
24:         AccountStorage.layout().balances[user] += amountWith18Decimals;
25:     }
```

If the user deposits a small number of collateral tokens to the contract, the `amountWith18Decimals` in Line 22 might round down to zero. In this case, the collateral tokens have been transferred to the protocol, but the account balance did not increase in Line 24.

## Impact

Loss of funds if the collateral is updated to a token with decimals more than 18 in the future. Since it requires certain specific conditions for the issue to be exploitable, marking this issue as a Medium instead of a High.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L27

## Tool used

Manual Review

## Recommendation

Consider implementing one of the following fixes to mitigate the issue

#### Solution 1

Update the affected function to revert if rounding errors occur.

```diff
function withdraw(address user, uint256 amount) internal {
	..SNIP..
    uint256 amountWith18Decimals = (amount * 1e18) /
    (10 ** IERC20Metadata(appLayout.collateral).decimals());
+	require(amountWith18Decimals > 0, "Rounding Error Occur")
    accountLayout.balances[msg.sender] -= amountWith18Decimals;
    IERC20(appLayout.collateral).safeTransfer(user, amount);
}
```

```diff
function deposit(address user, uint256 amount) internal {
    GlobalAppStorage.Layout storage appLayout = GlobalAppStorage.layout();
    IERC20(appLayout.collateral).safeTransferFrom(msg.sender, address(this), amount);
    uint256 amountWith18Decimals = (amount * 1e18) /
    (10 ** IERC20Metadata(appLayout.collateral).decimals());
+	require(amountWith18Decimals > 0, "Rounding Error Occur")
    AccountStorage.layout().balances[user] += amountWith18Decimals;
}
```

#### Solution 2

If the protocol does not intend to support collateral tokens with more than 18 decimals, explicitly disallow anyone from configuring such tokens in the future to prevent malicious user from exploiting this issue.

```solidity
function setCollateral(
    address collateral
) external onlyRole(LibAccessibility.DEFAULT_ADMIN_ROLE) {
    GlobalAppStorage.layout().collateral = collateral;
    require(IERC20Metadata(appLayout.collateral).decimals() <= 18, "Token with more than 18 decimals not allowed")
    emit SetCollateral(collateral);
}
```

# Issue M-18: Leverage for market orders might deviate 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/246 

## Found by 
berndartmueller, pengun, rvierdiiev, xiaoming90
## Summary

The leverage for market orders might deviate as the locked values are not adjusted according to the change in the market price, resulting in unexpected losses.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L112

```solidity
File: PartyBFacetImpl.sol
112:     function openPosition(
113:         uint256 quoteId,
114:         uint256 filledAmount,
115:         uint256 openedPrice,
116:         PairUpnlAndPriceSig memory upnlSig
117:     ) internal returns (uint256 currentId) {
..SNIP..
136:         if (quote.positionType == PositionType.LONG) {
137:             require(
138:                 openedPrice <= quote.requestedOpenPrice,
139:                 "PartyBFacet: Opened price isn't valid"
140:             );
141:         } else {
142:             require(
143:                 openedPrice >= quote.requestedOpenPrice,
144:                 "PartyBFacet: Opened price isn't valid"
145:             );
146:         }
..SNIP..
158:         if (quote.quantity == filledAmount) {
159:             accountLayout.pendingLockedBalances[quote.partyA].subQuote(quote);
160:             accountLayout.partyBPendingLockedBalances[quote.partyB][quote.partyA].subQuote(quote);
161: 
162:             if (quote.orderType == OrderType.LIMIT) {
163:                 quote.lockedValues.mul(openedPrice).div(quote.requestedOpenPrice);
164:             }
```

The leverage of a position is computed based on the following formula.

$leverage = \frac{price \times quantity}{lockedValues.total()}$

When opening a position, there is a possibility that the leverage might change because the locked values and quantity are fixed, but it could get filled with a different market price compared to the one at the moment the user requested.

To ensure that a fixed leverage is maintained, the `quote.lockedValues` is being adjusted proportionally to the `openedPrice`. The `quote.lockedValues` could adjust upward or downward during the adjustment.

However, the issue is that the adjustment is only being performed for limit orders but not for market orders. 

## Impact

The leverage factor of a market order position that is executed on-chain might end up deviating from the one at the moment the user requested due to the fluctuation of the market price. As a result, users might end up opening a position with a leverage factor higher or lower than they originally configured.

The leverage factor determines the extent of exposure to the position; thus, it might potentially magnify losses if a losing position has higher leverage than expected OR lose out on potential gain if a winning position has a lower leverage than expected.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/PartyB/PartyBFacetImpl.sol#L112

## Tool used

Manual Review

## Recommendation

Consider adjusting locked values for market orders to maintain the leverage, similar to what has been done for the limit orders.

# Issue M-19: `depositAndAllocateForPartyB` can be called against a liquidatable account 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/247 

## Found by 
AkshaySrivastav, tvdung94, xiaoming90
## Summary

Users might lose their funds if they use the `depositAndAllocateForPartyB` function to increase their allocated balance while their accounts have been marked as liquidatable.

## Vulnerability Detail

When liquidating PartyB, the account will be frozen once the `liquidatePartyB` function is executed, and the account's liquidation status will be set to `true` as shown in Line 272 below.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L272

```solidity
File: LiquidationFacetImpl.sol
240:     function liquidatePartyB(
241:         address partyB,
242:         address partyA,
243:         SingleUpnlSig memory upnlSig
244:     ) internal {
..SNIP..
272:         maLayout.partyBLiquidationStatus[partyB][partyA] = true;
273:         maLayout.partyBLiquidationTimestamp[partyB][partyA] = upnlSig.timestamp;
```

When a PartyB is marked as liquidatable, PartyB cannot deposit and allocate additional funds to their accounts. If PartyB attempts to do so, it will be denied by the `notLiquidatedPartyB` modifier on the `allocateForPartyB` function.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L66

```solidity
File: AccountFacet.sol
65:     // PartyB
66:     function allocateForPartyB(
67:         uint256 amount,
68:         address partyA
69:     ) public whenNotPartyBActionsPaused notLiquidatedPartyB(msg.sender, partyA) onlyPartyB {
70:         AccountFacetImpl.allocateForPartyB(amount, partyA, true);
71:         emit AllocateForPartyB(msg.sender, partyA, amount);
72:     }
```

Some users might use the convenient method called `depositAndAllocateForPartyB` to execute both deposit and allocate actions simultaneously. However, this function is not guarded by the `notLiquidatedPartyB` modifier. Thus, the users might call this function to increase their allocated balance while their accounts have been marked as liquidatable.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L74

```solidity
74:     function depositAndAllocateForPartyB(
75:         uint256 amount,
76:         address partyA
77:     ) external whenNotPartyBActionsPaused onlyPartyB {
78:         AccountFacetImpl.depositForPartyB(amount);
79:         AccountFacetImpl.allocateForPartyB(amount, partyA, true);
80:         emit DepositForPartyB(msg.sender, amount);
81:         emit AllocateForPartyB(msg.sender, partyA, amount);
82:     }
```

## Impact

If an account is marked as liquidatable, it is essentially considered frozen, and the users are not allowed to increase their allocated balance. Increasing the allocated balance of an account in this state would not help to bring the account back to a healthy threshold, even if a large sum of funds is injected into the account. 

When a user attempts to increase their allocated balance while their accounts have already been marked as liquidatable, there is a high possibility that the newly injected allocated balance will be lost as it will be used to pay the counterparty during liquidation.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L74

## Tool used

Manual Review

## Recommendation

Consider preventing users marked as liquidatable from calling the `depositAndAllocateForPartyB`. This measure has been implemented for all the other deposit and allocate related functions, except for the `depositAndAllocateForPartyB` function.

```diff
function depositAndAllocateForPartyB(
    uint256 amount,
    address partyA
- ) external whenNotPartyBActionsPaused onlyPartyB {
+ ) external whenNotPartyBActionsPaused notLiquidatedPartyB(msg.sender, partyA) onlyPartyB  {
    AccountFacetImpl.depositForPartyB(amount);
    AccountFacetImpl.allocateForPartyB(amount, partyA, true);
    emit DepositForPartyB(msg.sender, amount);
    emit AllocateForPartyB(msg.sender, partyA, amount);
}
```

# Issue M-20: Position value can fall below the minimum acceptable quote value 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/248 

## Found by 
0xcrunch, Ch\_301, Juntao, berndartmueller, bin2chen, circlelooper, mstpr-brainbot, shaka, volodya, xiaoming90
## Summary

PartyB can fill a LIMIT order position till the point where the value is below the minimum acceptable quote value (`minAcceptableQuoteValue`). As a result, it breaks the invariant that the value of position must be above the minimum acceptable quote value, leading to various issues and potentially losses for the users.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L196

```solidity
File: LibQuote.sol
149:     function closeQuote(Quote storage quote, uint256 filledAmount, uint256 closedPrice) internal {
..SNIP..
189:         if (quote.closedAmount == quote.quantity) {
190:             quote.quoteStatus = QuoteStatus.CLOSED;
191:             quote.requestedClosePrice = 0;
192:             removeFromOpenPositions(quote.id);
193:             quoteLayout.partyAPositionsCount[quote.partyA] -= 1;
194:             quoteLayout.partyBPositionsCount[quote.partyB][quote.partyA] -= 1;
195:         } else if (
196:             quote.quoteStatus == QuoteStatus.CANCEL_CLOSE_PENDING || quote.quantityToClose == 0
197:         ) {
198:             quote.quoteStatus = QuoteStatus.OPENED;
199:             quote.requestedClosePrice = 0;
200:             quote.quantityToClose = 0; // for CANCEL_CLOSE_PENDING status
201:         } else {
202:             require(
203:                 quote.lockedValues.total() >=
204:                     SymbolStorage.layout().symbols[quote.symbolId].minAcceptableQuoteValue,
205:                 "LibQuote: Remaining quote value is low"
206:             );
207:         }
208:     }
```

If the user has already sent the close request, but partyB has not filled it yet, the user can request to cancel it by calling the `CancelCloseRequest` function. This will cause the quote's status to change to `QuoteStatus.CANCEL_CLOSE_PENDING`.

PartyB can either accept the cancel request or fill the close request ignoring the user's request. If PartyB decided to go ahead to fill the close request partially, the second branch of the if-else statement at Line 196 will be executed. However, the issue is that within this branch, PartyB is not subjected to the `minAcceptableQuoteValue` validation check. Thus, it is possible for PartyB to fill a LIMIT order position till the point where the value is below the minimum acceptable quote value (`minAcceptableQuoteValue`).

## Impact

In the codebase, the `minAcceptableQuoteValue` is currently set to 5 USD. There are many reasons for having a minimum quote value in the first place. For instance, if the value of a position is too low, it will be uneconomical for the liquidator to liquidate the position because the liquidation fee would be too small or insufficient to cover the cost of liquidation. Note that the liquidation fee is computed as a percentage of the position value.

This has a negative impact on the overall efficiency of the liquidation mechanism within the protocol, which could delay or stop the liquidation of accounts or positions, exposing users to greater market risks, including the risk of incurring larger losses or having to exit at an unfavorable price. 

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L196

## Tool used

Manual Review

## Recommendation

If the user sends a close request and PartyB decides to go ahead to fill the close request partially, consider checking if the remaining value of the position is above the minimum acceptable quote value (`minAcceptableQuoteValue`) after PartyB has filled the position.

```diff
function closeQuote(Quote storage quote, uint256 filledAmount, uint256 closedPrice) internal {
	..SNIP..
    if (quote.closedAmount == quote.quantity) {
        quote.quoteStatus = QuoteStatus.CLOSED;
        quote.requestedClosePrice = 0;
        removeFromOpenPositions(quote.id);
        quoteLayout.partyAPositionsCount[quote.partyA] -= 1;
        quoteLayout.partyBPositionsCount[quote.partyB][quote.partyA] -= 1;
    } else if (
        quote.quoteStatus == QuoteStatus.CANCEL_CLOSE_PENDING || quote.quantityToClose == 0
    ) {
        quote.quoteStatus = QuoteStatus.OPENED;
        quote.requestedClosePrice = 0;
        quote.quantityToClose = 0; // for CANCEL_CLOSE_PENDING status
+        
+        require(
+            quote.lockedValues.total() >=
+                SymbolStorage.layout().symbols[quote.symbolId].minAcceptableQuoteValue,
+            "LibQuote: Remaining quote value is low"
+        );
    } else {
        require(
            quote.lockedValues.total() >=
                SymbolStorage.layout().symbols[quote.symbolId].minAcceptableQuoteValue,
            "LibQuote: Remaining quote value is low"
        );
    }
}
```

# Issue M-21: Changing of the collateral token will not work as intended 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/249 

## Found by 
AkshaySrivastav, innertia, xiaoming90
## Summary

Changing of the collateral token within the protocol might result in undesirable side effects (e.g. users unable to withdraw) or might not even be possible. The existing function only update the address of the collateral token, but lack of the necessary functions needed to carry out the migration of existing collateral tokens stored in the contracts.

## Vulnerability Detail

The protocol admin can call the `setCollateral` function to change the collateral token that the protocol uses at any time.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L95

```solidity
File: ControlFacet.sol
095:     function setCollateral(
096:         address collateral
097:     ) external onlyRole(LibAccessibility.DEFAULT_ADMIN_ROLE) {
098:         GlobalAppStorage.layout().collateral = collateral;
099:         emit SetCollateral(collateral);
100:     }
```

On the [Contest Page](https://audits.sherlock.xyz/contests/85), it was explicitly mentioned that USDT and USDC would be used within the protocol

> ### Q: Which ERC20 tokens do you expect will interact with the smart contracts?
>
> USDT and USDC

Assume that the current collateral token is USDC. The users have deposited and locked a total of 100,000,000 USDC into the contract (Note: It is not uncommon for a protocol to have a TLV of 100 million and above in DeFi)

The protocol decided to change the collateral token to USDT. After changing the collateral token, Alice decides to withdraw 100,000 USD from her account. In this case, Line 38 of the `withdraw` function below will be evaluated to as follows:

> IERC20(appLayout.collateral).safeTransfer(user, amount);
>
> IERC20(USDT.address).safeTransfer(Alice, 100,000);

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L27

```solidity
File: AccountFacetImpl.sol
27:     function withdraw(address user, uint256 amount) internal {
28:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
29:         GlobalAppStorage.Layout storage appLayout = GlobalAppStorage.layout();
30:         require(
31:             block.timestamp >=
32:             accountLayout.withdrawCooldown[msg.sender] + MAStorage.layout().deallocateCooldown,
33:             "AccountFacet: Cooldown hasn't reached"
34:         );
35:         uint256 amountWith18Decimals = (amount * 1e18) /
36:         (10 ** IERC20Metadata(appLayout.collateral).decimals());
37:         accountLayout.balances[msg.sender] -= amountWith18Decimals;
38:         IERC20(appLayout.collateral).safeTransfer(user, amount);
39:     }
```

However, the transaction will revert because there is no USDT token in the contract, and she will not be able to withdraw her funds.

Let's assume that the protocol admin is aware of this problem. Thus, before the protocol changes the collateral, the protocol has to inject 100,000,000 USDT into the contract before executing the change. 

It is unlikely for any project to be able to obtain 100 million worth of USDT from anywhere. Thus, a more practical approach would be to pass a governance action with a timelock to atomically pull 100 million USDC from the contract and swap it for 100 million USDT with some slippage control in place and inject the swapped USDT back into the contract. In this case, Alice will have no issue withdrawing her funds after the collateral token change.

However, the issue is that no function allows the protocol to withdraw existing collateral tokens from the contracts.

## Impact

If the collateral token changes, the users might be unable to withdraw their funds. In addition, the protocol lacks the functions needed to migrate to a new collateral token (e.g. ability to withdraw or transfer existing collateral tokens), so it might not be possible to switch to a new collateral token when there is an urgent need to do so (e.g. stablecoin depeg).

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L95

## Tool used

Manual Review

## Recommendation

Consider implementing some features (e.g. transfer, withdraw, swap) that allows the migration of existing collateral tokens to the new collateral tokens so that the withdrawal function would still work as usual after changing the collateral token of the protocol. Ensure that these features can only be triggered by the governance with a timelock mechanism to protect users' interests.

# Issue M-22: Ambiguous position index of a quote leading to unexpected errors 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/250 

## Found by 
xiaoming90
## Summary

The implementation of the `LibQuote.addToOpenPositions` and `LibQuote.removeFromOpenPositions` functions are incorrect and error-prone, which might cause the position to be removed from the account unexpectedly if a removed or non-existent quote ID is passed into the function. 

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L58

```solidity
File: LibQuote.sol
58:     function addToOpenPositions(uint256 quoteId) internal {
59:         QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
60:         Quote storage quote = quoteLayout.quotes[quoteId];
61: 
62:         quoteLayout.partyAOpenPositions[quote.partyA].push(quote.id);
63:         quoteLayout.partyBOpenPositions[quote.partyB][quote.partyA].push(quote.id);
64: 
65:         quoteLayout.partyAPositionsIndex[quote.id] = quoteLayout.partyAPositionsCount[quote.partyA];
66:         quoteLayout.partyBPositionsIndex[quote.id] = quoteLayout.partyBPositionsCount[quote.partyB][
67:             quote.partyA
68:         ];
69: 
70:         quoteLayout.partyAPositionsCount[quote.partyA] += 1;
71:         quoteLayout.partyBPositionsCount[quote.partyB][quote.partyA] += 1;
72:     }
```

When the quote is first added to the account, the `partyAPositionsCount` is zero, and thus it is placed in position 0.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L74

```solidity
File: LibQuote.sol
74:     function removeFromOpenPositions(uint256 quoteId) internal {
75:         QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
76:         Quote storage quote = quoteLayout.quotes[quoteId];
77:         uint256 indexOfPartyAPosition = quoteLayout.partyAPositionsIndex[quote.id];
78:         uint256 indexOfPartyBPosition = quoteLayout.partyBPositionsIndex[quote.id];
79:         uint256 lastOpenPositionIndex = quoteLayout.partyAPositionsCount[quote.partyA] - 1;
80:         quoteLayout.partyAOpenPositions[quote.partyA][indexOfPartyAPosition] = quoteLayout
81:             .partyAOpenPositions[quote.partyA][lastOpenPositionIndex];
82:         quoteLayout.partyAPositionsIndex[
83:             quoteLayout.partyAOpenPositions[quote.partyA][lastOpenPositionIndex]
84:         ] = indexOfPartyAPosition;
85:         quoteLayout.partyAOpenPositions[quote.partyA].pop();
86: 
87:         lastOpenPositionIndex = quoteLayout.partyBPositionsCount[quote.partyB][quote.partyA] - 1;
88:         quoteLayout.partyBOpenPositions[quote.partyB][quote.partyA][
89:             indexOfPartyBPosition
90:         ] = quoteLayout.partyBOpenPositions[quote.partyB][quote.partyA][lastOpenPositionIndex];
91:         quoteLayout.partyBPositionsIndex[
92:             quoteLayout.partyBOpenPositions[quote.partyB][quote.partyA][lastOpenPositionIndex]
93:         ] = indexOfPartyBPosition;
94:         quoteLayout.partyBOpenPositions[quote.partyB][quote.partyA].pop();
95: 
96:         quoteLayout.partyAPositionsIndex[quote.id] = 0;
97:         quoteLayout.partyBPositionsIndex[quote.id] = 0;
98:     }
```

When a quote is removed from the account, the `quoteLayout.partyAPositionsIndex[quote.id]` and `quoteLayout.partyBPositionsIndex[quote.id]` is set to zero. Setting it to zero also means that the removed quote ended up in position 0 after the transaction was executed.

In addition, if a quote does not exist in the first place or is not added to the account, the `quoteLayout.partyBPositionsIndex` and `quoteLayout.partyBPositionsIndex` will return zero because it has not been initialized yet.

This is an issue because when the `quoteLayout.partyBPositionsIndex` and `quoteLayout.partyBPositionsIndex` of a quote return zero, the result is inconclusive and ambiguous. This is because the result of zero can mean any of the following three (3) states, which might cause an unexpected error.

1) Quote exists and is stored in Position 0
2) Quote exists, but removed
3) Non-existent quote (Does not exist in the first place)

For instance, if a removed or non-existent quote ID is passed into the `LibQuote.removeFromOpenPositions` function, the function will not revert. Instead, the quote stored in position zero will end up being removed from the account, which is not the expected outcome.

## Impact

The implementation of the `LibQuote.addToOpenPositions` and `LibQuote.removeFromOpenPositions` functions are incorrect and error-prone, which might cause the position to be removed from the account unexpectedly if a removed or non-existent quote ID is passed into the function. 

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L74

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L74

## Tool used

Manual Review

## Recommendation

Consider having the first quote in the account starts at position 1 or index 1. Reserve position 0 or index 0 for a non-existent quote or quote that has been removed. 

When the `quoteLayout.partyBPositionsIndex` and `quoteLayout.partyBPositionsIndex` of a quote return zero, the `removeFromOpenPositions` function could revert to avoid any potential error.



## Discussion

**MoonKnightDev**

Indeed, the functions that utilize these two functions (removeFromOpenPositions & addToOpenPositions) carry out the necessary checks themselves to ensure that an unrelated quote id isn't passed. Your statement holds true, if an unrelated quote id were passed.

**hrishibhat**

@xiaoming9090 

# Issue M-23: Rounding error when closing quote 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/251 

## Found by 
xiaoming90
## Summary

Rounding errors could occur if the provided `filledAmount` is too small, resulting in the locked balance of an account remains the same even though a certain amount of the position has been closed.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L155

```solidity
File: LibQuote.sol
149:     function closeQuote(Quote storage quote, uint256 filledAmount, uint256 closedPrice) internal {
150:         QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
151:         AccountStorage.Layout storage accountLayout = AccountStorage.layout();
152: 
153:         quote.modifyTimestamp = block.timestamp;
154: 
155:         LockedValues memory lockedValues = LockedValues(
156:             quote.lockedValues.cva -
157:                 ((quote.lockedValues.cva * filledAmount) / (LibQuote.quoteOpenAmount(quote))),
158:             quote.lockedValues.mm -
159:                 ((quote.lockedValues.mm * filledAmount) / (LibQuote.quoteOpenAmount(quote))),
160:             quote.lockedValues.lf -
161:                 ((quote.lockedValues.lf * filledAmount) / (LibQuote.quoteOpenAmount(quote)))
162:         );
163:         accountLayout.lockedBalances[quote.partyA].subQuote(quote).add(lockedValues);
164:         accountLayout.partyBLockedBalances[quote.partyB][quote.partyA].subQuote(quote).add(
165:             lockedValues
166:         );
167:         quote.lockedValues = lockedValues;
168: 
169:         (bool hasMadeProfit, uint256 pnl) = LibQuote.getValueOfQuoteForPartyA(
170:             closedPrice,
171:             filledAmount,
172:             quote
173:         );
174:         if (hasMadeProfit) {
175:             accountLayout.allocatedBalances[quote.partyA] += pnl;
176:             accountLayout.partyBAllocatedBalances[quote.partyB][quote.partyA] -= pnl;
177:         } else {
178:             accountLayout.allocatedBalances[quote.partyA] -= pnl;
179:             accountLayout.partyBAllocatedBalances[quote.partyB][quote.partyA] += pnl;
180:         }

```

In Lines 157, 159, and 161 above, a malicious user could make the numerator smaller than the denominator (`LibQuote.quoteOpenAmount(quote)`), and the result will be zero due to a rounding error in Solidity.

In this case, the `quote.lockedValues` will not decrease and will remain the same. As a result, the locked balance of the account will remain the same even though a certain amount of the position has been closed. This could cause the account's locked balance to be higher than expected, and the errors will accumulate if it happens many times.

## Impact

When an account's locked balances are higher than expected, their available balance will be lower than expected. The available balance affects the amount that users can withdraw from their accounts. The "silent" increase in their locked values means that the amount that users can withdraw becomes lesser over time, and these amounts are lost due to the errors.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/libraries/LibQuote.sol#L155

## Tool used

Manual Review

## Recommendation

When the `((quote.lockedValues.cva * filledAmount) / (LibQuote.quoteOpenAmount(quote)))` rounds down to zero, this means that a rounding error has occurred as the numerator is smaller than the denominator. The CVA, `filledAmount` or both might be too small.

Consider performing input validation against the `filledAmount` within the `fillCloseRequest` function to ensure that the provided values are sufficiently large and will not result in a rounding error.

# Issue M-24: Deposit restriction can be bypassed 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/252 

## Found by 
xiaoming90
## Summary

The protocols only allowed whitelisted PartyB to deposit to its account. However, this restriction can be bypassed. If anyone could deposit funds into PartyB account, it would introduce all sorts of problems. For instance, a malicious user or competitor might intentionally inject ill-gotten gains or dirty funds into PartyB account in an attempt to cause indirect financial or reputational loss to the entities (e.g. being fined, blacklisted, or forced to shut down).

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L93

```solidity
File: AccountFacet.sol
93:     function depositForPartyB(uint256 amount) external whenNotPartyBActionsPaused onlyPartyB {
94:         AccountFacetImpl.depositForPartyB(amount);
95:         emit DepositForPartyB(msg.sender, amount);
96:     }
```

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L74

```solidity
File: AccountFacet.sol
74:     function depositAndAllocateForPartyB(
75:         uint256 amount,
76:         address partyA
77:     ) external whenNotPartyBActionsPaused onlyPartyB {
78:         AccountFacetImpl.depositForPartyB(amount);
79:         AccountFacetImpl.allocateForPartyB(amount, partyA, true);
80:         emit DepositForPartyB(msg.sender, amount);
81:         emit AllocateForPartyB(msg.sender, partyA, amount);
82:     }
```

Based on the design of the protocol, only whitelisted PartyB can deposit to its account. The `onlyPartyB` modifer in the `depositForPartyB` and `depositAndAllocateForPartyB` will ensure that only whitelisted PartyBs can access these two functions.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/utils/Accessibility.sol#L13

```solidity
File: Accessibility.sol
13:     modifier onlyPartyB() {
14:         require(MAStorage.layout().partyBStatus[msg.sender], "Accessibility: Should be partyB");
15:         _;
16:     }
```

In addition, the use of `msg.sender` will ensure that authorized PartyB can only deposit into their own account. They cannot deposit to some other PartyB accounts.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L108

```solidity
File: AccountFacetImpl.sol
108:     function depositForPartyB(uint256 amount) internal {
109:         IERC20(GlobalAppStorage.layout().collateral).safeTransferFrom(
110:             msg.sender,
111:             address(this),
112:             amount
113:         );
114:         uint256 amountWith18Decimals = (amount * 1e18) /
115:         (10 ** IERC20Metadata(GlobalAppStorage.layout().collateral).decimals());
116:         AccountStorage.layout().balances[msg.sender] += amountWith18Decimals;
117:     }
```

However, all the above-mentioned restrictions can be bypassed. Since the underlying implementation of PartyA's `deposit` and PartyB's `depositForPartyB` functions are exactly the same, they can be used interchangeably. Anyone can call the permissionless `AccountFacet.deposit` function and set the `user` parameter to a PartyB address to deposit to any PartyB's account.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L19

```solidity
File: AccountFacetImpl.sol
19:     function deposit(address user, uint256 amount) internal {
20:         GlobalAppStorage.Layout storage appLayout = GlobalAppStorage.layout();
21:         IERC20(appLayout.collateral).safeTransferFrom(msg.sender, address(this), amount);
22:         uint256 amountWith18Decimals = (amount * 1e18) /
23:         (10 ** IERC20Metadata(appLayout.collateral).decimals());
24:         AccountStorage.layout().balances[user] += amountWith18Decimals;
25:     }
```

## Impact

Unauthorized users could deposit funds into any PartyB account. PartyB is usually a hedger that could possibly be a trading firm or traditional finance/CFD brokerages. These entities are usually subjected to some form of regulatory oversight. Thus, the influx and outflow of funds to their account must be managed carefully to ensure compliance with the regulatory requirements.

If anyone could deposit funds into PartyB account, it would introduce all sorts of problems. For instance, a malicious user or competitor might intentionally inject ill-gotten gains or dirty funds into PartyB account in an attempt to cause indirect financial or reputational loss to the entities (e.g. being fined, bad PR, blacklisted, or forced to shut down).

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacetImpl.sol#L19

## Tool used

Manual Review

## Recommendation

Ensure that no one can use the permissionless PartyA's `deposit` function to deposit funds to PartyB account.

```diff
function deposit(address user, uint256 amount) internal {
+	require(!MAStorage.layout().partyBStatus[user], "Cannot deposit into PartyB");
    GlobalAppStorage.Layout storage appLayout = GlobalAppStorage.layout();
    IERC20(appLayout.collateral).safeTransferFrom(msg.sender, address(this), amount);
    uint256 amountWith18Decimals = (amount * 1e18) /
    (10 ** IERC20Metadata(appLayout.collateral).decimals());
    AccountStorage.layout().balances[user] += amountWith18Decimals;
}
```

# Issue M-25: DOS attack due to lack of penalty for `unlock` 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/253 

## Found by 
mstpr-brainbot, rvierdiiev, xiaoming90
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



## Discussion

**MoonKnightDev**

We currently don't apply any penalty for unlocking. This is because party B may lock one limit position at a time and when they attempt to open it, they may find that the user is no longer solvent. In such a case, party B is not acting maliciously, but needs to unlock it.

Now, regarding the DOS attack prevention methods you mentioned, we have the following measures in place:

1- Users have the option not to include potentially malicious party B in their whitelisted hedgers.

2- The protocol can identify and deregister party Bs who consistently engage in this behaviour and are deemed malicious.
In fact, we might consider imposing penalties on these party Bs, particularly if they have placed a collateral stake with us outside of the contract.

# Issue M-26: Cooldown periods initialize to 95129375 Years 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/254 

## Found by 
Kose, PokemonAuditSimulator, xiaoming90
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



## Discussion

**MoonKnightDev**

These were only initialized for testing purposes, and in the final product, they will be set to logical values.

**ctf-sec**

Emm I think I will use the snapshot of the current codebase as reference, so will maintain the medium severity for now

# Issue M-27: Malicious PartyB cannot be removed from the protocol 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/255 

## Found by 
0xmuxyz, xiaoming90
## Summary

It is not possible to remove a malicious PartyB completely from the system. In the event that a PartyB turns rogue and starts performing certain actions that harm the protocol or lead to the loss of assets, it might delay or complicate the recovery process or even be unable to stop the attack in the worst-case scenario.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L59

```solidity
File: ControlFacet.sol
59:     function registerPartyB(
60:         address partyB
61:     ) external onlyRole(LibAccessibility.PARTY_B_MANAGER_ROLE) {
62:         require(
63:             !MAStorage.layout().partyBStatus[partyB],
64:             "ControlFacet: Address is already registered"
65:         );
66:         MAStorage.layout().partyBStatus[partyB] = true;
67:         MAStorage.layout().partyBList.push(partyB);
68:         emit RegisterPartyB(partyB);
69:     }
```

To become a PartyB, the users must be registered by the protocol manager via `registerPartyB`. 

However, the protocol only has a method to register a PartyB, but does not have a method to de-register a PartyB

## Impact

In the event that a PartyB turns rogue and starts performing certain actions that harm the protocol or lead to the loss of assets, there is no way to remove the malicious PartyB from the system entirely. The protocol only has the option to suspend the malicious PartyB from calling the `withdraw` function, which might not be sufficient to guard against more sophisticated attacks.

To prove that it is insufficient, assume that the protocol suspends the malicious PartyB in an attempt to block them from calling the `withdraw` function. The attacker could exploit the issue I covered in another report to bypass this function by calling the `transferAllocation` function to transfer the assets to another account and use it to withdraw them. 

Even if the protocol has vetted PartyB at the time of registration, there is still a possibility that the private keys of PartyB be compromised by internal or external malicious actors later.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/control/ControlFacet.sol#L59

## Tool used

Manual Review

## Recommendation

Consider implementing a new method to de-register PartyB. 

Following is the pseudo-code of the de-register method:

```solidity
function deregisterPartyB(
    address partyB
) external onlyRole(LibAccessibility.PARTY_B_MANAGER_ROLE) {
    require(
        MAStorage.layout().partyBStatus[partyB],
        "ControlFacet: Address is not registered"
    );
    MAStorage.layout().partyBStatus[partyB] = false;
    MAStorage.layout().partyBList.remove(partyB);
    emit DeregisterPartyB(partyB);
}
```

# Issue M-28: PartyB can deposit even when partyB deposits are paused 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/268 

## Found by 
AkshaySrivastav, ast3ros
## Summary
All partyBs can deposit tokens even when `partyBActionsPaused` is set to true.

## Vulnerability Detail
Deposits of both partyA and partyB are stored in a common `balances` mapping.

The `AccountFacet.depositForPartyB` function has `whenNotPartyBActionsPaused` modifier which prevents the party deposits when partyB actions are paused.

```solidity
    function depositForPartyB(uint256 amount) external whenNotPartyBActionsPaused onlyPartyB {
        AccountFacetImpl.depositForPartyB(amount);
        emit DepositForPartyB(msg.sender, amount);
    }
```
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/Account/AccountFacet.sol#L93-L96

However this `whenNotPartyBActionsPaused` limitation can be bypassed by directly depositing using the `deposit` function.

## Impact
PartyB can deposit tokens even when the protocol wants to prevent them from depositing.

## Code Snippet
Provided above.

## Tool used

Manual Review

## Recommendation
Consider adding `notPartyB` modifier to the `deposit` function so that it cannot be used by partyB.

# Issue M-29: Liquidator may receive incorrect fee in party B liquidation due to party A liquidation interference 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/276 

## Found by 
ast3ros
## Summary

When party B is in the process of liquidation and party A is also liquidated, the liquidator may receive an incorrect liquidation fee.

## Vulnerability Detail

The liquidation of party B involves two stages: `liquidatePartyB` and `liquidatePositionsPartyB`. These are two different (no atomic) transactions.

- In stage 1 - `liquidatePartyB`, the `partyBPositionLiquidatorsShare` is calculated by the formula `(remainingLf - liquidatorShare)/partyBPositionsCount` (which is the average of lf per position)

        maLayout.partyBPositionLiquidatorsShare[partyB][partyA] =
            (remainingLf - liquidatorShare) /
            quoteLayout.partyBPositionsCount[partyB][partyA];

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L265-L267

- In stage 2: the liquidator receives the amount `partyBPositionLiquidatorsShare` * number of liquidation quotes.

        accountLayout.allocatedBalances[msg.sender] +=
            maLayout.partyBPositionLiquidatorsShare[partyB][partyA] *
            priceSig.quoteIds.length;

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L374-L376

The issue is that party A can be liquidated while party B is in the liquidation process.

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacet.sol#L13-L24

If party A is liquidated and completed between stage 1 and stage 2 of party B’s liquidation (party B stage 1 -> party A liquidate position -> party B stage 2), and party A has a position with party B, then the `partyBPositionLiquidatorsShare` does not reflect the correct Lf per outstanding B position because when party A is liquidated, it reduces the `partyBPositionsCount` and adjusts the `partyBAllocatedBalances`.

        quoteLayout.partyBPositionsCount[quote.partyB][partyA] -= 1;

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L209
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L163-L197

Therefore, the liquidator in stage 2 receives `partyBPositionLiquidatorsShare` which is outdated.

## Impact

The liquidator in stage 2 may receive an incorrect amount of liquidation fee.

## Code Snippet

https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L265-L267
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L374-L376
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacet.sol#L13-L24
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L209
https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L163-L197

## Tool used

Manual Review

## Recommendation

When party B is liquidating in stage 1, change the status to `LIQUIDATING` and prevent party A from liquidating this position.

# Issue M-30: Liquidating a turned solvent Party A does not credit the profits to Party A 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/290 

## Found by 
berndartmueller, libratus
## Summary

Party A can turn solvent again mid-way through the multi-step liquidation process. While Party B will have its [losses deducted from its allocated balance](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L170), Party A will not receive any profits. Instead, its allocated balance is [reset to 0](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L216).

## Vulnerability Detail

If Party A turns solvent again, i.e., its available balance (`availableBalance`) is positive, after a liquidator has started the liquidation and calls the `setSymbolsPrice` to initialize the symbol prices as well as Party A's liquidation details, the liquidation will proceed as usual. Liquidating the individual open positions of Party A with the `liquidatePositionsPartyA` function deducts the losses from the trading counterparty B's allocated balance in line 170.

However, the profits made by Party A are not credited to Party A's allocated balance. Instead, Party A's allocated balance is reset to 0 in line 216 once all positions are liquidated.

## Impact

Party A's realized profits during the liquidation are retained by the protocol instead of credited to Party A's allocated balance.

## Code Snippet

[contracts/facets/liquidation/LiquidationFacetImpl.sol#L65-L67](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L65-L67)

Party A, who turned solvent, will have the liquidation proceed as usual, with the `liquidationType` set to `NORMAL`.

```solidity
34: function setSymbolsPrice(address partyA, PriceSig memory priceSig) internal {
...     // [...]
51:
52:     int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
53:         priceSig.upnl,
54:         partyA
55:     );
56:     if (accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NONE) {
57:         accountLayout.liquidationDetails[partyA] = LiquidationDetail({
58:             liquidationType: LiquidationType.NONE,
59:             upnl: priceSig.upnl,
60:             totalUnrealizedLoss: priceSig.totalUnrealizedLoss,
61:             deficit: 0,
62:             liquidationFee: 0
63:         });
64: @>      if (availableBalance >= 0) {
65: @>          uint256 remainingLf = accountLayout.lockedBalances[partyA].lf;
66: @>          accountLayout.liquidationDetails[partyA].liquidationType = LiquidationType.NORMAL;
67: @>          accountLayout.liquidationDetails[partyA].liquidationFee = remainingLf;
68:         } else if (uint256(-availableBalance) < accountLayout.lockedBalances[partyA].lf) {
...     // [...]
97: }
```

[contracts/facets/liquidation/LiquidationFacetImpl.sol#L170](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L170)

Liquidating Party A's positions, which are in a profit (and thus a loss for Party B), deducts the losses from Party B's allocated balance in line 170. The profit is **not** credited to Party A.

```solidity
File: LiquidationFacetImpl.sol
126: function liquidatePositionsPartyA(
127:     address partyA,
128:     uint256[] memory quoteIds
129: ) internal returns (bool) {
130:     AccountStorage.Layout storage accountLayout = AccountStorage.layout();
131:     MAStorage.Layout storage maLayout = MAStorage.layout();
132:     QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
133:
134:     require(maLayout.liquidationStatus[partyA], "LiquidationFacet: PartyA is solvent");
135:     for (uint256 index = 0; index < quoteIds.length; index++) {
136:         Quote storage quote = quoteLayout.quotes[quoteIds[index]];
...          // [...]
162:
163:         if (
164:             accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NORMAL
165:         ) {
166:             accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += quote
167:                 .lockedValues
168:                 .cva;
169:             if (hasMadeProfit) {
170: @>              accountLayout.partyBAllocatedBalances[quote.partyB][partyA] -= amount; // @audit-info Party B's allocated balance is decreased by the amount of profit made by party A
171:             } else {
172:                 accountLayout.partyBAllocatedBalances[quote.partyB][partyA] += amount;
173:             }
```

[contracts/facets/liquidation/LiquidationFacetImpl.sol#L216](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L216)

Once all of Party A's positions are liquidated, Party A's allocated balance is reset to 0 in line 216.

```solidity
126: function liquidatePositionsPartyA(
127:     address partyA,
128:     uint256[] memory quoteIds
129: ) internal returns (bool) {
...   // [...]
211:  if (quoteLayout.partyAPositionsCount[partyA] == 0) {
212:      require(
213:          quoteLayout.partyAPendingQuotes[partyA].length == 0,
214:          "LiquidationFacet: Pending quotes should be liquidated first"
215:      );
216:  @>  accountLayout.allocatedBalances[partyA] = 0;
217:      accountLayout.lockedBalances[partyA].makeZero();
218:
219:      uint256 lf = accountLayout.liquidationDetails[partyA].liquidationFee;
220:      if (lf > 0) {
221:          accountLayout.allocatedBalances[accountLayout.liquidators[partyA][0]] += lf / 2;
222:          accountLayout.allocatedBalances[accountLayout.liquidators[partyA][1]] += lf / 2;
223:      }
224:      delete accountLayout.liquidators[partyA];
225:      maLayout.liquidationStatus[partyA] = false;
226:      maLayout.liquidationTimestamp[partyA] = 0;
227:      accountLayout.liquidationDetails[partyA].liquidationType = LiquidationType.NONE;
228:      if (
229:          accountLayout.totalUnplForLiquidation[partyA] !=
230:          accountLayout.liquidationDetails[partyA].upnl
231:      ) {
232:          accountLayout.totalUnplForLiquidation[partyA] = 0;
233:          return false;
234:      }
235:      accountLayout.totalUnplForLiquidation[partyA] = 0;
236:  }
237:  return true;
```

## Tool used

Manual Review

## Recommendation

Consider adding Party A's realized profits during the liquidation to Party A's allocated balance.

# Issue M-31: Consecutive symbol price updates can be exploited to drain protocol funds 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/291 

## Found by 
berndartmueller
## Summary

Repeatedly updating the symbol prices for the symbols used in Party A's positions mid-way through a liquidation while maintaining the same Party A's UPnL and total unrealized losses leads to more profits for Party B and effectively steals funds from the protocol.

## Vulnerability Detail

The `setSymbolsPrice` function in the `LiquidationFacetImpl` library is used to set the prices of symbols for Party A's positions. It is called by the liquidator, who supplies the `PriceSig memory priceSig` argument, which contains, among other values, the prices of the symbols as well as the `upnl` and `totalUnrealizedLoss` of Party A's positions.

Party A's `upnl` and `totalUnrealizedLoss` values are [stored in Party A's liquidation details](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L59-L60) and enforced to remain the same for consecutive calls to `setSymbolsPrice` via the `require` statement in lines 90-95.

However, as long as those two values remain the same, the liquidator can set the prices of the symbols to the current market prices (fetched by the Muon app). If a liquidator liquidates Party A's open positions in multiple calls to `liquidatePositionsPartyA` and updates symbol prices in between, Party B potentially receives more profits than they should have.

The git diff below contains a test case to demonstrate the following scenario:

Given the following symbols:

1. `BTCUSDT`
2. `AAVEUSDT`

For simplicity, we assume trading fees are 0.

Party A's allocated balance: `100e18 USDT`

Party A has two open positions with Party B:

| ID  | Symbol   | Order Type | Position Type | Quantity | Price | Total Value | CVA   | LF    | MM  | Total Locked | Leverage |
| --- | -------- | ---------- | ------------- | -------- | ----- | ----------- | ----- | ----- | --- | ------------ | -------- |
| 1   | BTCUSDT  | LIMIT      | LONG          | 100e18   | 1e18  | 100e18      | 25e18 | 25e18 | 0   | 50e18        | 2        |
| 2   | AAVEUSDT | LIMIT      | LONG          | 100e18   | 1e18  | 100e18      | 25e18 | 25e18 | 0   | 50e18        | 2        |

Party A's available balance: 100e18 - 100e18 = 0 USDT

Now, the price of `BTCUSDT` drops by 40% to `0.6e18 USDT`. Party A's `upnl` and `totalUnrealizedLoss` are now `-40e18 USDT` and `-40e18 USDT`, respectively.

Party A is insolvent and gets liquidated.

The liquidator calls `setSymbolsPrice` for both symbols, setting the price of `BTCUSDT` to `0.6e18 USDT` and the price of `AAVEUSDT` to `1e18 USDT`. The `liquidationDetails` of Party A are as follows:

- `liquidationType`: `LiquidationType.NORMAL`
- `upnl`: `-40e18 USDT`
- `totalUnrealizedLoss`: `-40e18 USDT`
- `deficit`: 0
- `liquidationFee`: `50e18 - 40e18 = 10e18 USDT`

The liquidator first liquidates position 1 -> Party B receives `40e18 USDT` + `25e18 USDT` (CVA) = `65e18 USDT`

Now, due to a volatile market, the price of `AAVEUSDT` drops by 40% to `0.6e18 USDT`. The liquidator calls `setSymbolsPrice` again, setting the price of `AAVEUSDT` to `0.6e18 USDT`. `upnl` and `totalUnrealizedLoss` remain the same. Thus the symbol prices can be updated.

The liquidator liquidates position 2 -> Party B receives `40e18 USDT` + `25e18 USDT` (CVA) = `65e18 USDT`

Party B received in total `65e18 + 65e18 = 130e18 USDT`, which is `30e18` USDT more than Party A's initially locked balances. Those funds are effectively stolen from the protocol and bad debt.

Conversely, if both positions had been liquidated in the first call without updating the symbol prices in between, Party B would have received `40e18 + 25e18 = 65e18 USDT`, which Party A's locked balances covered.

<details>
  <summary><strong>Git diff</strong></summary>

```diff
diff --git a/symmio-core/test/Initialize.fixture.ts b/symmio-core/test/Initialize.fixture.ts
index 2df1e6f..cfe81c0 100644
--- a/symmio-core/test/Initialize.fixture.ts
+++ b/symmio-core/test/Initialize.fixture.ts
@@ -45,7 +45,11 @@ export async function initializeFixture(): Promise<RunContext> {

 await context.controlFacet
   .connect(context.signers.admin)
-    .addSymbol("BTCUSDT", decimal(5), decimal(1, 16), decimal(1, 16));
+    .addSymbol("BTCUSDT", decimal(5), decimal(1, 16), decimal(0));
+
+    await context.controlFacet
+    .connect(context.signers.admin)
+    .addSymbol("AAVEUSDT", decimal(5), decimal(1, 16), decimal(0));

 await context.controlFacet.connect(context.signers.admin).setPendingQuotesValidLength(10);
 await context.controlFacet.connect(context.signers.admin).setLiquidatorShare(decimal(1, 17));
diff --git a/symmio-core/test/LiquidationFacet.behavior.ts b/symmio-core/test/LiquidationFacet.behavior.ts
index 2e06b92..08e40d2 100644
--- a/symmio-core/test/LiquidationFacet.behavior.ts
+++ b/symmio-core/test/LiquidationFacet.behavior.ts
@@ -7,8 +7,10 @@ import { Hedger } from "./models/Hedger";
import { RunContext } from "./models/RunContext";
import { BalanceInfo, User } from "./models/User";
import { decimal, getTotalLockedValuesForQuoteIds, getTradingFeeForQuotes, liquidatePartyA } from "./utils/Common";
-import { getDummySingleUpnlSig } from "./utils/SignatureUtils";
+import { getDummyPriceSig, getDummySingleUpnlSig } from "./utils/SignatureUtils";
import hre from "hardhat";
+import { limitQuoteRequestBuilder } from "./models/requestModels/QuoteRequest";
+import { limitOpenRequestBuilder } from "./models/requestModels/OpenRequest";

export function shouldBehaveLikeLiquidationFacet(): void {
 beforeEach(async function() {
@@ -16,7 +18,7 @@ export function shouldBehaveLikeLiquidationFacet(): void {

   this.user = new User(this.context, this.context.signers.user);
   await this.user.setup();
-    await this.user.setBalances(decimal(2000), decimal(1000), decimal(500));
+    await this.user.setBalances(decimal(2000), decimal(100), decimal(100));

   this.user2 = new User(this.context, this.context.signers.user2);
   await this.user2.setup();
@@ -39,20 +41,26 @@ export function shouldBehaveLikeLiquidationFacet(): void {
   await this.hedger.openPosition(1);

   // Quote2 -> locked
-    await this.user.sendQuote();
+    await this.user.sendQuote(
+      limitQuoteRequestBuilder()
+        .symbolId(2)
+        .build()
+    );
   await this.hedger.lockQuote(2);
+    await this.hedger.openPosition(2,
+      limitOpenRequestBuilder().price(decimal(1)).build());

   // Quote3 -> sent
-    await this.user.sendQuote();
+    // await this.user.sendQuote();

   // Quote4 -> user2 -> opened
-    await this.user2.sendQuote();
-    await this.hedger.lockQuote(4);
-    await this.hedger.openPosition(4);
+    // await this.user2.sendQuote();
+    // await this.hedger.lockQuote(4);
+    // await this.hedger.openPosition(4);

   // Quote5 -> locked
-    await this.user.sendQuote();
-    await this.hedger.lockQuote(5);
+    // await this.user.sendQuote();
+    // await this.hedger.lockQuote(5);
 });

 describe("Liquidate PartyA", async function() {
@@ -116,16 +124,12 @@ export function shouldBehaveLikeLiquidationFacet(): void {
   describe("Liquidate Positions", async function() {
     beforeEach(async function() {
       const context: RunContext = this.context;
-        await liquidatePartyA(
-          context,
-          context.signers.user.getAddress(),
-        );
-        await liquidatePartyA(
-          context,
-          context.signers.user2.getAddress(),
-          context.signers.liquidator,
-          decimal(-475),
-        );
+        // await liquidatePartyA(
+        //   context,
+        //   context.signers.user2.getAddress(),
+        //   context.signers.liquidator,
+        //   decimal(-475),
+        // );
     });

     it("Should fail on invalid state", async function() {
@@ -179,6 +183,72 @@ export function shouldBehaveLikeLiquidationFacet(): void {
       let balanceInfoOfLiquidator = await this.liquidator.getBalanceInfo();
       expect(balanceInfoOfLiquidator.allocatedBalances).to.be.equal(decimal(1));
     });
+
+      it.only("Should maliciously liquidate positions", async function() {
+        const context: RunContext = this.context;
+        let user = context.signers.user.getAddress();
+        let hedger = context.signers.hedger.getAddress();
+
+        expect(await context.viewFacet.allocatedBalanceOfPartyA(user)).to.be.equal(
+          decimal(100),
+        );
+
+        await liquidatePartyA(
+          context,
+          context.signers.user.getAddress(),
+        );
+
+        await context.liquidationFacet
+          .connect(context.signers.liquidator)
+          .liquidatePendingPositionsPartyA(user);
+
+        expect(await context.viewFacet.allocatedBalanceOfPartyB(hedger, user)).to.be.equal(
+          decimal(240),
+        );
+
+        await context.liquidationFacet
+          .connect(context.signers.liquidator)
+          .liquidatePositionsPartyA(user, [1]);
+
+          expect((await context.viewFacet.isPartyALiquidated(user))).to.be.true;
+
+        expect((await context.viewFacet.getQuote(1)).quoteStatus).to.be.equal(
+          QuoteStatus.LIQUIDATED,
+        );
+
+        expect(await context.viewFacet.allocatedBalanceOfPartyB(hedger, user)).to.be.equal(
+          decimal(240 + 65), // @audit-info 65 profit: 40 profit from position + 25 CVA
+        );
+
+        expect(await context.viewFacet.allocatedBalanceOfPartyA(user)).to.be.equal(
+          decimal(100), // @audit-info remains unchanged until the liquidation process is complete
+        );
+
+        await context.liquidationFacet
+          .connect(context.signers.liquidator)
+          .setSymbolsPrice(
+            user,
+            await getDummyPriceSig([2], [decimal(6, 17)], decimal(-40), decimal(-40)), // @audit-info price of symbol #2 dropped by 40% (6e17) -> same UPnL and total loss
+          );
+
+        await context.liquidationFacet
+          .connect(context.signers.liquidator)
+          .liquidatePositionsPartyA(user, [2]);
+
+        expect((await context.viewFacet.getQuote(2)).quoteStatus).to.be.equal(
+          QuoteStatus.LIQUIDATED,
+        );
+
+        expect((await context.viewFacet.isPartyALiquidated(user))).to.be.false;
+
+        expect(await context.viewFacet.allocatedBalanceOfPartyB(hedger, user)).to.be.equal(
+          decimal(240 + 65 + 65), // @audit-info 130 profit in total: 80 profit from positions + 50 CVA
+        );
+
+        expect(await context.viewFacet.allocatedBalanceOfPartyA(user)).to.be.equal(
+          decimal(0),
+        );
+      });
   });
 });

diff --git a/symmio-core/test/models/requestModels/QuoteRequest.ts b/symmio-core/test/models/requestModels/QuoteRequest.ts
index 833e181..82d45b9 100644
--- a/symmio-core/test/models/requestModels/QuoteRequest.ts
+++ b/symmio-core/test/models/requestModels/QuoteRequest.ts
@@ -29,9 +29,9 @@ const limitDefaultQuoteRequest: QuoteRequest = {
 orderType: OrderType.LIMIT,
 price: decimal(1),
 quantity: decimal(100),
-  cva: decimal(22),
-  mm: decimal(75),
-  lf: decimal(3),
+  cva: decimal(25),
+  mm: decimal(0),
+  lf: decimal(25),
 maxInterestRate: 0,
 deadline: getBlockTimestamp(500),
 upnlSig: getDummySingleUpnlAndPriceSig(decimal(1)),
diff --git a/symmio-core/test/utils/Common.ts b/symmio-core/test/utils/Common.ts
index ed0c3c9..69f7ed5 100644
--- a/symmio-core/test/utils/Common.ts
+++ b/symmio-core/test/utils/Common.ts
@@ -119,10 +119,10 @@ export async function liquidatePartyA(
 context: RunContext,
 liquidatedUser: Promise<string>,
 liquidator: SignerWithAddress = context.signers.liquidator,
-  upnl: BigNumberish = decimal(-473),
-  totalUnrealizedLoss: BigNumberish = 0,
-  symbolIds: BigNumberish[] = [1],
-  prices: BigNumberish[] = [decimal(1)],
+  upnl: BigNumberish = decimal(-40),
+  totalUnrealizedLoss: BigNumberish = decimal(-40),
+  symbolIds: BigNumberish[] = [1, 2],
+  prices: BigNumberish[] = [decimal(6, 17), decimal(1)],
) {
 await context.liquidationFacet
   .connect(liquidator)
```

</details>

**How to run this test case:**

Save git diff to a file named `exploit-liquidation.patch` and run with

```bash
git apply exploit-liquidation.patch
npx hardhat test
```

## Impact

A malicious liquidator can cooperate with Party B and by exploiting this issue during a volatile market, can cause Party B to receive more funds (profits, due to being the counterparty to Party A which faces losses) than it should and steal funds from the protocol.

## Code Snippet

[contracts/facets/liquidation/LiquidationFacetImpl.sol#L90-L95](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L90-L95)

```solidity
34: function setSymbolsPrice(address partyA, PriceSig memory priceSig) internal {
35:     MAStorage.Layout storage maLayout = MAStorage.layout();
36:     AccountStorage.Layout storage accountLayout = AccountStorage.layout();
37:
38:     LibMuon.verifyPrices(priceSig, partyA);
39:     require(maLayout.liquidationStatus[partyA], "LiquidationFacet: PartyA is solvent");
40:     require(
41:         priceSig.timestamp <=
42:             maLayout.liquidationTimestamp[partyA] + maLayout.liquidationTimeout,
43:         "LiquidationFacet: Expired signature"
44:     );
45:     for (uint256 index = 0; index < priceSig.symbolIds.length; index++) {
46:         accountLayout.symbolsPrices[partyA][priceSig.symbolIds[index]] = Price(
47:             priceSig.prices[index],
48:             maLayout.liquidationTimestamp[partyA]
49:         );
50:     }
51:
52:     int256 availableBalance = LibAccount.partyAAvailableBalanceForLiquidation(
53:         priceSig.upnl,
54:         partyA
55:     );
56:     if (accountLayout.liquidationDetails[partyA].liquidationType == LiquidationType.NONE) {
57:         accountLayout.liquidationDetails[partyA] = LiquidationDetail({
58:             liquidationType: LiquidationType.NONE,
59:             upnl: priceSig.upnl,
60:             totalUnrealizedLoss: priceSig.totalUnrealizedLoss,
61:             deficit: 0,
62:             liquidationFee: 0
63:         });
...     // [...]
89:     } else {
90: @>      require(
91: @>          accountLayout.liquidationDetails[partyA].upnl == priceSig.upnl &&
92: @>              accountLayout.liquidationDetails[partyA].totalUnrealizedLoss ==
93: @>              priceSig.totalUnrealizedLoss,
94: @>          "LiquidationFacet: Invalid upnl sig"
95: @>      );
96:     }
97: }
```

## Tool used

Manual Review

## Recommendation

Consider preventing the liquidator from updating symbol prices mid-way of a liquidation process.

Or, alternatively, store the number of Party A's open positions in the `liquidationDetails` and only allow updating the symbol prices if the current number of open positions is still the same, effectively preventing the liquidator from updating the symbol prices once a position has been liquidated.



## Discussion

**MoonKnightDev**

The potential exploit you've mentioned hinges on the unlikely scenario that during the liquidation process, a party can provide a signature that exactly replicates the previous unrealized PnL and total unrealized loss. This is theoretically possible but practically near-impossible. Hence, we categorize this issue as medium risk.

**ctf-sec**

Comment from senior watson:

The risk should be medium as it requires a number of conditions must be aligned for the issue to occur:

1) The market must be volatile

2) For this attack to succeed, the upnl and totalUnrealizedLoss of the second price update must be the same as the first one. Even if the price moves, it is difficult to obtain the same upnl and totalUnrealizedLoss for a second time from the oracle as it has to be accurate to the smaller decimal (1 wei).

3) PartyA and PartyB must conspire. PartyB has to be whitelisted by the protocol team.

**ctf-sec**

Adjusted the risk to medium based on the comments above

# Issue M-32: Party B liquidation can expire, causing the liquidation to be stuck 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/293 

## Found by 
Ch\_301, Kose, Yuki, berndartmueller, bin2chen, cergyk, josephdara, libratus, panprog, shaka, simon135, sinarette, volodya, xiaoming90
## Summary

The liquidation of Party B can get stuck if the liquidation timeout is reached and the positions are not liquidated within the timeout period.

## Vulnerability Detail

The insolvent Party B's positions are liquidated by the liquidator via the `liquidatePositionsPartyB` function in the `LiquidationFacetImpl` library. This function requires supplying the `QuotePriceSig memory priceSig` parameter, which includes a timestamp and a signature from the Muon app. The signature is verified to ensure the `priceSig` values were actually fetched by the trusted Muon app.

The signature is expected to be created within the liquidation timeout period. This is verified through the validation of the `priceSig.timestamp`, as seen in lines 318-322. Failure to do so, i.e., providing a signature that's created beyond the liquidation timeout, results in the signature being treated as expired, thereby causing the function to revert and rendering the liquidation of Party B stuck.

## Impact

Party A's [locked balance is not decremented by the liquidatable position](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L348). Party B's liquidations status is stuck and remains set to `true`, resulting in the `notLiquidated` and `notLiquidatedPartyB` modifiers to revert.

## Code Snippet

[contracts/facets/liquidation/LiquidationFacetImpl.sol#L318-L322](https://github.com/sherlock-audit/2023-06-symmetrical/blob/main/symmio-core/contracts/facets/liquidation/LiquidationFacetImpl.sol#L318-L322)

```solidity
308: function liquidatePositionsPartyB(
309:     address partyB,
310:     address partyA,
311:     QuotePriceSig memory priceSig
312: ) internal {
313:     AccountStorage.Layout storage accountLayout = AccountStorage.layout();
314:     MAStorage.Layout storage maLayout = MAStorage.layout();
315:     QuoteStorage.Layout storage quoteLayout = QuoteStorage.layout();
316:
317:     LibMuon.verifyQuotePrices(priceSig);
318: @>  require(
319: @>      priceSig.timestamp <=
320: @>          maLayout.partyBLiquidationTimestamp[partyB][partyA] + maLayout.liquidationTimeout,
321: @>      "LiquidationFacet: Expired signature"
322: @>  );
323:     require(
324:         maLayout.partyBLiquidationStatus[partyB][partyA],
325:         "LiquidationFacet: PartyB is solvent"
326:     );
327:     require(
328:         block.timestamp <= priceSig.timestamp + maLayout.liquidationTimeout,
329:         "LiquidationFacet: Expired price sig"
330:     );
```

## Tool used

Manual Review

## Recommendation

Consider adding functionality to reset the liquidation status (i.e., `maLayout.partyBLiquidationStatus[partyB][partyA] = false` and `maLayout.partyBLiquidationTimestamp[partyB][partyA] = 0`) of Party B once the liquidation timeout is reached.

# Issue M-33: Fee collector can grief the protocol by withdrawing trading fees that could still need to be returned to Party A 

Source: https://github.com/sherlock-audit/2023-06-symmetrical-judging/issues/299 

## Found by 
AkshaySrivastav, Ch\_301, Lilyjjo, Ruhum, berndartmueller, bitsurfer, libratus, simon135
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

