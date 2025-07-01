#![allow(clippy::unwrap_used)]

use crate::common::wait_until_balance;
use bitcoin::key::Secp256k1;
use bitcoin::Amount;
use common::init_tracing;
use common::set_up_client;
use common::Nigiri;
use rand::thread_rng;
use std::sync::Arc;
use std::time::Duration;

mod common;

#[tokio::test]
#[ignore]
pub async fn send_subdust_amount() {
    init_tracing();
    let nigiri = Arc::new(Nigiri::new());

    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    let (alice, _) = set_up_client("alice".to_string(), nigiri.clone(), secp.clone()).await;
    let (bob, _) = set_up_client("bob".to_string(), nigiri.clone(), secp).await;

    let alice_fund_amount = Amount::ONE_BTC;

    nigiri
        .faucet_fund(&alice.get_boarding_address().unwrap(), alice_fund_amount)
        .await;

    alice.board(&mut rng, false).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    let alice_offchain_balance = alice.offchain_balance().await.unwrap();
    assert_eq!(alice_offchain_balance.confirmed(), alice_fund_amount);

    // Send Bob a sub-dust amount.
    let sub_dust_amount = Amount::ONE_SAT;
    let (bob_offchain_address, _) = bob.get_offchain_address().unwrap();

    alice
        .send_vtxo(bob_offchain_address, sub_dust_amount)
        .await
        .unwrap();

    // Available balance does not include sub-dust amounts, so we cannot wait on Bob's balance.
    wait_until_balance(&alice, Amount::ZERO, alice_fund_amount - sub_dust_amount).await;

    let (alice_offchain_address, _) = alice.get_offchain_address().unwrap();

    bob.send_vtxo(alice_offchain_address, sub_dust_amount)
        .await
        .expect_err("should not be able to send sub-dust amount");

    bob.board(&mut rng, true)
        .await
        .expect_err("should not be able to board sub-dust amount");

    // Send Bob a regular VTXO.
    let regular_amount = Amount::from_sat(100_000);

    alice
        .send_vtxo(bob_offchain_address, regular_amount)
        .await
        .unwrap();

    wait_until_balance(
        &alice,
        Amount::ZERO,
        alice_fund_amount - regular_amount - sub_dust_amount,
    )
    .await;
    wait_until_balance(&bob, Amount::ZERO, regular_amount).await;

    bob.board(&mut rng, true).await.unwrap();

    wait_until_balance(&bob, regular_amount + sub_dust_amount, Amount::ZERO).await;
}
