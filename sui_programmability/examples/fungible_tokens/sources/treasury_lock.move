// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// WARNING: Like all files in the examples section, this code is unaudited
/// and should NOT be running in production. Using the code unaudited could potentially
/// result in lost of funds from hacks, and leakage of transaction amounts.

/// An example implementation of a 'treasury lock'. It encapsulates the TreasuryCap
/// of a Coin so that additional whitelisted parties (bearers of the `MintCap`)
/// can mint new Coins up to a pre-defined per epoch limit. This can be used e.g.
/// to create a faucet.
module fungible_tokens::treasury_lock {
    use sui::object::{Self, UID, ID};
    use sui::coin::{Self, TreasuryCap};
    use sui::balance::{Balance};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::vec_set::{Self, VecSet};

    /// This mint capability instance is banned.
    const EMintCapBanned: u64 = 0;
    /// Requested mint amount exceeds the per epoch mint limit.
    const EMintAmountTooLarge: u64 = 1;

    /// Encapsulates the `TreasuryCap` and stores the list of banned mint authorities.
    struct TreasuryLock<phantom T> has key {
        id: UID,
        treasury_cap: TreasuryCap<T>,
        banned_mint_authorities: VecSet<ID>
    }

    /// Admin capability for `TreasuryLock`. Bearer has the power to create, ban,
    /// and unban mint capabilities (`MintCap`)
    struct LockAdminCap<phantom T> has key, store {
        id: UID
    }

    /// Capability allowing the bearer to mint new Coins up to a pre-defined per epoch limit.
    struct MintCap<phantom T> has key, store {
        id: UID,
        max_mint_per_epoch: u64,
        last_epoch: u64,
        minted_in_epoch: u64
    }

    /// Create a new `TreasuryLock` for `TreasuryCap`.
    public fun new_lock<T>(
        cap: TreasuryCap<T>, ctx: &mut TxContext
    ): LockAdminCap<T> {
        let lock = TreasuryLock {
            id: object::new(ctx),
            treasury_cap: cap,
            banned_mint_authorities: vec_set::empty<ID>()
        };
        transfer::share_object(lock);

        return LockAdminCap<T> {
            id: object::new(ctx),
        }
    }

    /// Create a new mint capability whose bearer will be allowed to mint
    /// max_mint_per_epoch coins per epoch.
    public fun create_mint_cap<T>(
        _cap: &LockAdminCap<T>, max_mint_per_epoch: u64, ctx: &mut TxContext
    ): MintCap<T> {
        MintCap<T>{
            id: object::new(ctx),
            max_mint_per_epoch,
            last_epoch: tx_context::epoch(ctx),
            minted_in_epoch: 0
        }
    }

    /// Ban a `MintCap`.
    public fun ban_mint_cap_id<T>(
        _cap: &LockAdminCap<T>, lock: &mut TreasuryLock<T>, id: ID
    ) {
        vec_set::insert(&mut lock.banned_mint_authorities, id)
    }

    /// Unban a previously banned `MintCap`.
    public fun unban_mint_cap_id<T>(
        _cap: &LockAdminCap<T>, lock: &mut TreasuryLock<T>, id: ID
    ) {
        vec_set::remove(&mut lock.banned_mint_authorities, &id)
    }

    /// Borrow the `TreasuryCap` to use directly.
    public fun borrow_treasury_cap<T>(
        _cap: &LockAdminCap<T>, lock: &mut TreasuryLock<T>
    ): &mut TreasuryCap<T> {
        &mut lock.treasury_cap
    }

    /// Mint a `Balance` from a `TreasuryLock` providing a `MintCap`.
    public fun mint_balance<T>(
        lock: &mut TreasuryLock<T>, cap: &mut MintCap<T>, amount: u64, ctx: &mut TxContext
    ): Balance<T> {
        assert!(
            !vec_set::contains(&lock.banned_mint_authorities, object::uid_as_inner(&cap.id)),
            EMintCapBanned
        );

        let epoch = tx_context::epoch(ctx);
        if (cap.last_epoch != epoch) {
            cap.last_epoch = epoch;
            cap.minted_in_epoch = 0;
        };
        assert!(
            cap.minted_in_epoch + amount <= cap.max_mint_per_epoch,
            EMintAmountTooLarge
        );

        cap.minted_in_epoch = cap.minted_in_epoch + amount;
        coin::mint_balance(&mut lock.treasury_cap, amount)
    }
}

#[test_only]
module fungible_tokens::treasury_lock_tests {
    use sui::test_scenario::{Self, Scenario};
    use sui::balance::{Self, Balance};
    use sui::transfer;
    use sui::coin;
    use sui::object::{Self};
    use fungible_tokens::treasury_lock::{Self, TreasuryLock, LockAdminCap, MintCap, create_mint_cap, new_lock, mint_balance};

    const ADMIN: address = @0xABBA;
    const USER: address = @0xB0B;

    // one time witness for the coin used in tests
    struct TREASURY_LOCK_TESTS has drop {}

    fun user_with_mint_cap_scenario(): Scenario {
        let scenario_ = test_scenario::begin(&ADMIN);
        let scenario = &mut scenario_;

        // create a currency and lock it
        test_scenario::next_tx(scenario, &ADMIN);
        {
            let treasury = coin::create_currency(TREASURY_LOCK_TESTS {}, 0, test_scenario::ctx(scenario));
            let admin_cap = new_lock(treasury, test_scenario::ctx(scenario));
            transfer::transfer(
                admin_cap,
                ADMIN
            )
        };

        // create a mint capability and transfer it to user
        test_scenario::next_tx(scenario, &ADMIN);
        {
            let admin_cap = test_scenario::take_owned<LockAdminCap<TREASURY_LOCK_TESTS>>(scenario);
            let mint_cap = create_mint_cap(&admin_cap, 500, test_scenario::ctx(scenario));
            transfer::transfer(
                mint_cap,
                USER
            );
            test_scenario::return_owned(scenario, admin_cap);
        };

        return scenario_
    }

    fun user_mint_balance(scenario: &mut Scenario, amount: u64): Balance<TREASURY_LOCK_TESTS> {
        let mint_cap = test_scenario::take_owned<MintCap<TREASURY_LOCK_TESTS>>(scenario);
        let lock = test_scenario::take_shared<TreasuryLock<TREASURY_LOCK_TESTS>>(scenario);

        let balance = mint_balance(
            test_scenario::borrow_mut(&mut lock),
            &mut mint_cap,
            amount,
            test_scenario::ctx(scenario)
        );

        test_scenario::return_owned(scenario, mint_cap);
        test_scenario::return_shared(scenario, lock);

        return balance
    }


    #[test]
    fun test_user_can_mint() {
        let scenario = &mut user_with_mint_cap_scenario();

        // user uses its capability to mint 300 coins
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 300);
            assert!(balance::value<TREASURY_LOCK_TESTS>(&balance) == 300, 0);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        };

    }

    #[test]
    #[expected_failure(abort_code = 1)]
    fun test_minting_over_limit_fails() {
        let scenario = &mut user_with_mint_cap_scenario();

        // mint 300 coins
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 300);
            assert!(balance::value<TREASURY_LOCK_TESTS>(&balance) == 300, 0);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        };

        // mint 200 more
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 200);
            assert!(balance::value<TREASURY_LOCK_TESTS>(&balance) == 200, 0);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        };

        // attempt to mint amount over the epoch limit - should fail
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 1);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        };
    }

    #[test]
    fun test_minted_amount_resets_at_epoch_change() {
        let scenario = &mut user_with_mint_cap_scenario();

        // mint 300 coins
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 300);
            assert!(balance::value<TREASURY_LOCK_TESTS>(&balance) == 300, 0);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        };

        // next epoch and mint 300 again
        test_scenario::next_epoch(scenario);
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 300);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        } 
    }

    #[test]
    #[expected_failure(abort_code = 0)]
    fun test_banned_cap_cannot_mint() {
        let scenario = &mut user_with_mint_cap_scenario();

        // get the mint cap ID for reference
        test_scenario::next_tx(scenario, &USER);
        let mint_cap = test_scenario::take_owned<MintCap<TREASURY_LOCK_TESTS>>(scenario);
        let mint_cap_id = object::id(&mint_cap);
        test_scenario::return_owned(scenario, mint_cap);


        // mint 100 coins
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 100);
            assert!(balance::value<TREASURY_LOCK_TESTS>(&balance) == 100, 0);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        };

        // admin bans mint cap
        test_scenario::next_tx(scenario, &ADMIN);
        {
            let admin_cap = test_scenario::take_owned<LockAdminCap<TREASURY_LOCK_TESTS>>(scenario);
            let lock = test_scenario::take_shared<TreasuryLock<TREASURY_LOCK_TESTS>>(scenario);

            treasury_lock::ban_mint_cap_id(
                &admin_cap,
                test_scenario::borrow_mut(&mut lock),
                mint_cap_id
            );

            test_scenario::return_owned(scenario, admin_cap);
            test_scenario::return_shared(scenario, lock);
        };

        // user attempts to mint but fails
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 100);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        };
    }

    #[test]
    fun test_user_can_mint_after_unban() {
        let scenario = &mut user_with_mint_cap_scenario();

        // get the mint cap ID for reference
        test_scenario::next_tx(scenario, &USER);
        let mint_cap = test_scenario::take_owned<MintCap<TREASURY_LOCK_TESTS>>(scenario);
        let mint_cap_id = object::id(&mint_cap);
        test_scenario::return_owned(scenario, mint_cap);

        // mint 100 coins
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 100);
            assert!(balance::value<TREASURY_LOCK_TESTS>(&balance) == 100, 0);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        };

        // admin bans mint cap
        test_scenario::next_tx(scenario, &ADMIN);
        {
            let admin_cap = test_scenario::take_owned<LockAdminCap<TREASURY_LOCK_TESTS>>(scenario);
            let lock = test_scenario::take_shared<TreasuryLock<TREASURY_LOCK_TESTS>>(scenario);

            treasury_lock::ban_mint_cap_id(
                &admin_cap,
                test_scenario::borrow_mut(&mut lock),
                mint_cap_id
            );

            test_scenario::return_owned(scenario, admin_cap);
            test_scenario::return_shared(scenario, lock);
        };

        // admin unbans mint cap
        test_scenario::next_tx(scenario, &ADMIN);
        {
            let admin_cap = test_scenario::take_owned<LockAdminCap<TREASURY_LOCK_TESTS>>(scenario);
            let lock = test_scenario::take_shared<TreasuryLock<TREASURY_LOCK_TESTS>>(scenario);

            treasury_lock::unban_mint_cap_id(
                &admin_cap,
                test_scenario::borrow_mut(&mut lock),
                mint_cap_id
            );

            test_scenario::return_owned(scenario, admin_cap);
            test_scenario::return_shared(scenario, lock);
        };

        // user can mint
        test_scenario::next_tx(scenario, &USER);
        {
            let balance = user_mint_balance(scenario, 100);
            assert!(balance::value<TREASURY_LOCK_TESTS>(&balance) == 100, 0);

            transfer::transfer(
                coin::from_balance(balance, test_scenario::ctx(scenario)),
                USER
            );
        };
    }
}