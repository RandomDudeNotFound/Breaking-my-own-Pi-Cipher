# Pi-Based Key Schedule Experiments

Student research project by Alexander. Tests whether a key schedule built on the digits of pi holds up against an attacker who knows the whole algorithm.

The full write-up is in [`pi-keyed-key-schedule-paper.md`](../pi-keyed-key-schedule-paper.md).

**This is an educational experiment, not a security product. Do not use it to protect real data.**

## What's here

`main.cpp` contains two experiments (no external libraries):

1. **Known-window attack** on the naive linear walk `x(t) = x0 + c*t`. The attacker sees a few short windows of output and recovers the secret start `x0` and speed `c` by searching the public pi table.
2. **Histogram-filter attack** on a keyed shuffle / substitution of a pi window with no hash stage. The attacker uses digit counts, which shuffling cannot hide, to narrow down where in pi the window came from.

## Build (Visual Studio, Windows)

1. Create a new **Console App** (C++) project.
2. Replace the generated source file's contents with `main.cpp`.
3. Set the build to **Release** (much faster) and run.

Optional argument: number of pi digits to generate (default 50000; bigger is slower, since the spigot algorithm is O(n^2)). You can also drop a `pi.txt` with digits next to the executable and it will be used instead.

## Build (command line, g++)

```
g++ -std=c++14 -O2 main.cpp -o pi_exp
./pi_exp 50000
```

## Output

Console tables plus `results_exp1.csv` and `results_exp2.csv` for plotting (Excel, Python/matplotlib, etc.). The random generator uses a fixed seed so results are reproducible.

## Sample result (20,000 digits of pi)

- Experiment 1: with only 4 observed digits per step over 3 steps, the attacker recovered `(x0, c)` uniquely in 100% of trials, in about 16 microseconds.
- Experiment 2: shuffling alone leaks about 14 of the ~14.3 bits of position information. Adding a digit substitution helps for short windows, but leakage grows with window length (2.8 bits at 8 digits, 11.1 bits at 64).

## Limitations

- The pi table here is small (tens of thousands of digits). Larger tables need longer windows for the same effect, but the qualitative result holds.
- The histogram attacker is deliberately simple. Repetition-pattern attacks would leak more.
- Not yet implemented: the hardened HKDF ratchet, Shamir sharing, proactive refresh, and fingerprint renderer (see the paper's Section 5 and 7).

## References

See the paper.
