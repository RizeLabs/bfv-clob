use bfv::*;
use operators::*;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;

#[derive(Serialize, Deserialize, Debug)]
struct Orders {
    pair: String,
    buy_orders: Vec<u64>,
    sell_orders: Vec<u64>,
}

fn main() {
    // plaintext modulus
    let t = 65537;

    // no of slots
    let slots = 1 << 4;

    println!("slots: {}", slots);

    let mut rng = thread_rng();

    let mut params = BfvParameters::new(&[60; 10], t, slots);

    // P - 180 bits
    params.enable_hybrid_key_switching(&[60; 3]);

    // generate secret key
    let sk = SecretKey::random_with_params(&params, &mut rng);

    // Create evaluator to evaluate arithmetic operarions
    let evaluator = Evaluator::new(params);

    let ek = EvaluationKey::new(evaluator.params(), &sk, &[0], &[0], &[1], &mut rng);

    // Open and read the file containing the order
    let file_path = "order.json";
    let mut file = File::open(file_path).expect("File not found");

    // Read the contents of the file into a string
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file");

    // Parse the JSON data into your data structure
    let order_data: Orders = serde_json::from_str(&contents).expect("Failed to parse JSON");

    // plain buy and sell orders
    let buy_orders_plain = order_data.buy_orders;
    let sell_orders_plain = order_data.sell_orders;

    let order_len = buy_orders_plain.len();

    // Preparing buy orders for encoding
    let buy_orders_formatted_plain = buy_orders_plain
        .iter()
        .map(|x| {
            let mut val = vec![0; slots];
            val[0] = *x;
            val
        })
        .collect::<Vec<Vec<u64>>>();

    // Preparing sell orders for encoding
    let sell_orders_formatted_plain = sell_orders_plain
        .iter()
        .map(|x| {
            let mut val = vec![0; slots];
            val[0] = *x;
            val
        })
        .collect::<Vec<Vec<u64>>>();

    // encoding buy orders
    let encoded_buy_orders: Vec<Plaintext> = buy_orders_formatted_plain
        .iter()
        .map(|x| evaluator.plaintext_encode(&x, Encoding::default()))
        .collect::<Vec<Plaintext>>();

    // encoding sell orders
    let encoded_sell_orders: Vec<Plaintext> = sell_orders_formatted_plain
        .iter()
        .map(|x| evaluator.plaintext_encode(&x, Encoding::default()))
        .collect::<Vec<Plaintext>>();

    // encrypting buy orders
    let encrypted_buy_orders: Vec<Ciphertext> = encoded_buy_orders
        .iter()
        .map(|x| evaluator.encrypt(&sk, &x, &mut rng))
        .collect::<Vec<Ciphertext>>();

    // encrypting sell orders
    let encrypted_sell_orders: Vec<Ciphertext> = encoded_sell_orders
        .iter()
        .map(|x| evaluator.encrypt(&sk, &x, &mut rng))
        .collect::<Vec<Ciphertext>>();

    // summing up buy order value
    let sum_buy_orders = encrypted_buy_orders
        .iter()
        .skip(1)
        .fold(encrypted_buy_orders[0].clone(), |acc, x| {
            evaluator.add(&acc, &x)
        });

    // summing up sell order value
    let sum_sell_orders = encrypted_sell_orders
        .iter()
        .skip(1)
        .fold(encrypted_sell_orders[0].clone(), |acc, x| {
            evaluator.add(&acc, &x)
        });

    let is_buy_sum_less_encrypted =
        univariate_less_than(&evaluator, &sum_buy_orders, &sum_sell_orders, &ek, &sk);
    let is_buy_sum_less_plain = evaluator.plaintext_decode(
        &evaluator.decrypt(&sk, &is_buy_sum_less_encrypted),
        Encoding::default(),
    );

    match is_buy_sum_less_plain[0] {
        0 => {
            let transaction_volume = evaluator.plaintext_decode(
                &evaluator.decrypt(&sk, &sum_buy_orders),
                Encoding::default(),
            );

            println!("Transaction Volume: {:?}", transaction_volume[0]);
        }
        1 => {
            let transaction_volume = evaluator.plaintext_decode(
                &evaluator.decrypt(&sk, &sum_sell_orders),
                Encoding::default(),
            );

            println!("Transaction Volume: {:?}", transaction_volume[0]);
        }
        _ => println!("This condition is not possible!!"),
    }

    let mut sum_sell_orders_temp = sum_sell_orders.clone();
    let mut sum_buy_orders_temp = sum_buy_orders.clone();

    let mut buy_orders_filling_encrypted: Vec<Ciphertext> = vec![];
    let mut sell_orders_filling_encrypted: Vec<Ciphertext> = vec![];

    println!("Trying to fill Buy orders !!");

    for (index, order) in encrypted_buy_orders.iter().enumerate() {
        // let filled_order = univariate_less_than(&evaluator, order, &sum_sell_orders_temp, &ek, &sk);
        // is order < sum_sell_orders_temp
        let is_less_encrypted =
            univariate_less_than(&evaluator, order, &sum_sell_orders_temp, &ek, &sk); // passing sk just to keep check on noise not to decrypt the order
        let is_less_plain = evaluator.plaintext_decode(
            &evaluator.decrypt(&sk, &is_less_encrypted),
            Encoding::default(),
        );

        match is_less_plain[0] {
            0 => {
                let zero_value_order = vec![0; slots];
                let zero_value_order_encoded = evaluator.plaintext_encode(&zero_value_order, Encoding::default());
                let zero_value_order_encrypted = evaluator.encrypt(&sk, &zero_value_order_encoded, &mut rng);
                // impossible to fill this order
                buy_orders_filling_encrypted.push(zero_value_order_encrypted);
            }
            1 => {
                sum_sell_orders_temp = evaluator.sub(&sum_sell_orders_temp, order);
                buy_orders_filling_encrypted.push(order.clone());
            }
            _ => println!("This condition is not possible!!"),
        }
        println!("Filled {:?}th Buy Order  ", index);
    }

    println!("Now trying to fill Sell orders !!");

    for (index, order) in encrypted_sell_orders.iter().enumerate() {
        let is_less_encrypted =
            univariate_less_than(&evaluator, order, &sum_buy_orders_temp, &ek, &sk); // passing sk just to keep check on noise not to decrypt the order
        let is_less_plain = evaluator.plaintext_decode(
            &evaluator.decrypt(&sk, &is_less_encrypted),
            Encoding::default(),
        );

        match is_less_plain[0] {
            0 => {
                let zero_value_order = vec![0; slots];
                let zero_value_order_encoded = evaluator.plaintext_encode(&zero_value_order, Encoding::default());
                let zero_value_order_encrypted = evaluator.encrypt(&sk, &zero_value_order_encoded, &mut rng);
                // impossible to fill this order
                buy_orders_filling_encrypted.push(zero_value_order_encrypted);
            }
            1 => {
                sum_buy_orders_temp = evaluator.sub(&sum_buy_orders_temp, order);
                sell_orders_filling_encrypted.push(order.clone());
            }
            _ => println!("This condition is not possible!!"),
        }
        println!("Filled {:?}th Buy Order  ", index);
    }

    let buy_orders_filled_plain = buy_orders_filling_encrypted
        .iter()
        .map(|x| evaluator.plaintext_decode(&evaluator.decrypt(&sk, &x), Encoding::default())[0])
        .collect::<Vec<u64>>();

    let sell_orders_filled_plain = sell_orders_filling_encrypted
        .iter()
        .map(|x| evaluator.plaintext_decode(&evaluator.decrypt(&sk, &x), Encoding::default())[0])
        .collect::<Vec<u64>>();

    println!("Buy/Sell orders which could be filled are mentioned with their order value rest which can't be filled are mentioned with value 0");
    println!("Buy orders plain {:?} ", buy_orders_filled_plain);
    println!("Sell orders plain {:?} ", sell_orders_filled_plain);
}
