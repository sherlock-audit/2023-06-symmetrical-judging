xiaoming90

high

# `depositAndAllocateForPartyB` is broken due to incorrect precision

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