# Private CLOB

Implementation of simple matching algorithm which can find match for encrypted orders. Algorithm proposed in this [paper](https://eprint.iacr.org/2022/923.pdf). This matching algorithms is implemented with bfv fully homomorphic encryption algorithm to facilitate order matching
for encrypted orders. We used [bfv](https://github.com/Janmajayamall/bfv) and [operator](https://github.com/Janmajayamall/caird/tree/main/operators) library by [Janmajayamall](https://github.com/Janmajayamall)

## 🧑‍💻 Usage

1. Define `buy` and `sell` orders [here](https://github.com/Banana-Wallet/bfv-clob/blob/main/private-clob/order.json)
2. Build project by running `cargo build` in `bfv`, `caird/operators` and `private-clob` directories. As the algorithm uses `bfv` and `operators` library and apis.
3. Run the matching algorithm using `cargo run` in `private-clob` directory. For you convenience some sample orders has been already defined in `order.json`.

## 📝 Interpretation 

On successfull execution of the algorithm you'll see two arrays buy and sell array. In which non-zero element conveys order settlement and zero elements indicates that the order can't be fullfilled.

