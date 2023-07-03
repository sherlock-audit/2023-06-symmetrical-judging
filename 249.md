xiaoming90

medium

# Changing of the collateral token will not work as intended

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