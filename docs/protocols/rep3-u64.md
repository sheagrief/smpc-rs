# Rep3 over `u64`

## Sharing

For a value `x` in `Z / 2^64 Z`, choose additive shares:

```text
x0 + x1 + x2 = x mod 2^64
```

Party `i` holds the replicated pair:

```text
(x_i, x_{i+1 mod 3})
```

Opening broadcasts each party's `x_i` component and reconstructs:

```text
x = x0 + x1 + x2 mod 2^64
```

## Local Operations

Addition, subtraction, and multiplication by public constants are local on the
replicated share components. Adding or subtracting a public constant adjusts
only additive component `x0`, which is held by parties 0 and 2.

## Multiplication

Each party locally computes:

```text
v_i = x_i y_i + x_i y_{i+1} + x_{i+1} y_i
```

Then:

```text
sum_i v_i = x * y mod 2^64
```

To reshare the local `v_i` values, party `i` derives PRSS masks:

- `r_{i-1}` from the seed shared with the previous party
- `r_i` from the seed shared with the next party

and computes:

```text
z_i = v_i + r_i - r_{i-1}
```

The masks telescope, so:

```text
sum_i z_i = sum_i v_i = x * y
```

Party `i` sends `z_i` to party `i-1`, so every party obtains `(z_i, z_{i+1})`.

## PRSS Domain Separation

PRSS streams are domain-separated by:

- pair seed
- session id
- operation label
- monotonic operation counter
- pair owner

All parties must execute networked MPC operations in the same order.
