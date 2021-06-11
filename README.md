# ZKDT

This is an implementation of [Zero Knowledge Proofs for Decision Tree Predictions and Accuracy](https://dl.acm.org/doi/pdf/10.1145/3372297.3417278). 


This repo builds on [libsnark](https://github.com/scipr-lab/libsnark). 

## Compile and run
In the `ZKDT` folder, run the following commands:
```
mkdir build && cd build && cmake ..
```

```
make
```

### Single prediction
To check single path prediction, run
```
./src/dt_path
```
This will generate the R1CS to prove the prediction for a single data point. A synthetic instance and some real instances are used for test.

### Batch prediction
To check the batched version, run
```
./src/dt_batch
```
This will generate the R1CS to prove the prediction for a batch . Also, a synthetic instance and some real instances are used for test. Compared to repetition of single prediction, this performs better when there are many instances and the entire tree is not large.


