// pi_experiments.cpp
// Author: Alexander
//
// Experiment 1: Known-window attack against the naive linear pi walk
//               x(t) = x0 + c*t   (recover x0 and c from a few observed windows)
// Experiment 2: Histogram-filter attack against a keyed shuffle/substitution
//               of a pi window (no hash stage), measuring how much it leaks.
//
// No external libraries. Compiles as C++14 or later (Visual Studio: Console App).
// NOTE: std::mt19937_64 is NOT cryptographically secure. It is used here only so
// the experiments are reproducible. Never use it to generate real keys.

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Pi digits
// ---------------------------------------------------------------------------

// Rabinowitz-Wagon spigot algorithm. O(n^2), fine for tens of thousands of digits.
// Returns n digits starting with the leading "3" (no decimal point).
static std::string generatePi(int n) {
    const int extra = 8;               // compute a few extra digits, trim later
    const int total = n + extra;
    const int len = total * 10 / 3 + 1;
    std::vector<std::uint64_t> a(len, 2);
    std::string out;
    out.reserve(total + 2);
    int nines = 0;
    int predigit = 0;

    for (int j = 1; j <= total; ++j) {
        std::uint64_t q = 0;
        for (int i = len; i >= 1; --i) {
            std::uint64_t x = 10 * a[i - 1] + q * i;
            a[i - 1] = x % (2 * i - 1);
            q = x / (2 * i - 1);
        }
        a[0] = q % 10;
        q /= 10;
        if (q == 9) {
            ++nines;
        } else if (q == 10) {
            out.push_back(static_cast<char>('0' + predigit + 1));
            for (int k = 0; k < nines; ++k) out.push_back('0');
            predigit = 0;
            nines = 0;
        } else {
            out.push_back(static_cast<char>('0' + predigit));
            predigit = static_cast<int>(q);
            for (int k = 0; k < nines; ++k) out.push_back('9');
            nines = 0;
        }
    }
    out.push_back(static_cast<char>('0' + predigit));

    out.erase(out.begin());            // drop the leading 0
    out.resize(n);                     // drop the unreliable trailing digits
    return out;
}

// Optional: load digits from a text file (e.g. downloaded pi digits).
static std::string loadPiFromFile(const std::string& path) {
    std::ifstream f(path);
    std::string digits, line;
    while (std::getline(f, line))
        for (char ch : line)
            if (ch >= '0' && ch <= '9') digits.push_back(ch);
    return digits;
}

// ---------------------------------------------------------------------------
// Experiment 1: known-window attack on x(t) = x0 + c*t
// ---------------------------------------------------------------------------
//
// The naive scheme outputs, at step t, the w-digit window pi[x(t) .. x(t)+w).
// The attacker knows the algorithm and the public pi table, and observes
// T consecutive windows. Goal: recover (x0, c).
//
static void experiment1(const std::string& pi, std::mt19937_64& rng) {
    const int T = 3;          // number of observed steps
    const int CMAX = 16;      // speed c is in [1, CMAX]
    const int TRIALS = 300;
    const int L = static_cast<int>(pi.size());
    const int windows[] = {1, 2, 3, 4, 5, 6, 8, 10};

    std::ofstream csv("results_exp1.csv");
    csv << "window_digits,avg_candidates,percent_fully_recovered,avg_attack_microseconds\n";

    std::cout << "\n=== Experiment 1: known-window attack on the linear pi walk ===\n";
    std::cout << "Table size L = " << L << " digits, observed steps T = " << T
              << ", c in [1," << CMAX << "], trials = " << TRIALS << "\n";
    std::cout << "Secret space (x0,c): about " << std::fixed << std::setprecision(1)
              << std::log2(static_cast<double>(L) * CMAX) << " bits\n\n";
    std::cout << std::left << std::setw(10) << "window"
              << std::setw(22) << "avg candidates left"
              << std::setw(22) << "% fully recovered"
              << "avg attack time (us)\n";

    for (int w : windows) {
        double sumCand = 0.0, sumMicros = 0.0;
        int recovered = 0;

        for (int trial = 0; trial < TRIALS; ++trial) {
            const int c = 1 + static_cast<int>(rng() % CMAX);
            const int span = c * (T - 1) + w;
            const int x0 = static_cast<int>(rng() % static_cast<std::uint64_t>(L - span + 1));

            std::vector<std::string> obs(T);
            for (int t = 0; t < T; ++t) obs[t] = pi.substr(x0 + c * t, w);

            // ---- the attack ----
            auto start = std::chrono::steady_clock::now();
            int candidates = 0;
            bool trueFound = false;
            std::size_t pos = pi.find(obs[0]);
            while (pos != std::string::npos) {
                for (int c2 = 1; c2 <= CMAX; ++c2) {
                    if (static_cast<int>(pos) + c2 * (T - 1) + w > L) break;
                    bool ok = true;
                    for (int t = 1; t < T && ok; ++t)
                        ok = (pi.compare(pos + c2 * t, w, obs[t]) == 0);
                    if (ok) {
                        ++candidates;
                        if (static_cast<int>(pos) == x0 && c2 == c) trueFound = true;
                    }
                }
                pos = pi.find(obs[0], pos + 1);
            }
            auto end = std::chrono::steady_clock::now();
            // --------------------

            sumCand += candidates;
            sumMicros += std::chrono::duration<double, std::micro>(end - start).count();
            if (candidates == 1 && trueFound) ++recovered;
        }

        const double avgCand = sumCand / TRIALS;
        const double pct = 100.0 * recovered / TRIALS;
        const double avgUs = sumMicros / TRIALS;
        std::cout << std::left << std::setw(10) << w
                  << std::setw(22) << std::setprecision(2) << avgCand
                  << std::setw(22) << std::setprecision(1) << pct
                  << std::setprecision(1) << avgUs << "\n";
        csv << w << "," << avgCand << "," << pct << "," << avgUs << "\n";
    }
    std::cout << "\nSaved: results_exp1.csv\n";
}

// ---------------------------------------------------------------------------
// Experiment 2: histogram-filter attack on a keyed shuffle of a pi window
// ---------------------------------------------------------------------------
//
// Model: the window W = pi[pos .. pos+w) is transformed WITHOUT a hash stage:
//   Variant A: a secret permutation of the positions (shuffle)
//   Variant B: a secret digit substitution (0-9 relabeling) plus a shuffle
// The attacker sees W' and filters table positions using properties that these
// transforms cannot hide:
//   A: the exact digit histogram is unchanged
//   B: the histogram changes labels, but the SORTED histogram is unchanged
// We measure how many of the table's positions survive the filter.
//
using Hist = std::array<int, 10>;

static Hist sortedDesc(Hist h) {
    std::sort(h.begin(), h.end(), std::greater<int>());
    return h;
}

static void experiment2(const std::string& pi, std::mt19937_64& rng) {
    const int TRIALS = 200;
    const int L = static_cast<int>(pi.size());
    const int windows[] = {8, 12, 16, 24, 32, 48, 64};

    std::ofstream csv("results_exp2.csv");
    csv << "window_digits,variant,avg_survivor_percent,avg_bits_leaked\n";

    std::cout << "\n=== Experiment 2: histogram filter vs. keyed shuffle (no hash) ===\n";
    std::cout << "Table size L = " << L << ", trials = " << TRIALS << "\n";
    std::cout << "bits leaked = log2(total positions / surviving positions)\n\n";
    std::cout << std::left << std::setw(10) << "window"
              << std::setw(30) << "A: shuffle only"
              << "B: substitution + shuffle\n";
    std::cout << std::setw(10) << "" << std::setw(15) << "survivors %" << std::setw(15) << "bits"
              << std::setw(15) << "survivors %" << "bits\n";

    for (int w : windows) {
        const int positions = L - w + 1;
        double survA = 0.0, survB = 0.0, bitsA = 0.0, bitsB = 0.0;

        for (int trial = 0; trial < TRIALS; ++trial) {
            const int pos = static_cast<int>(rng() % static_cast<std::uint64_t>(positions));
            std::string window = pi.substr(pos, w);

            // Variant A: shuffle only
            std::string wa = window;
            std::shuffle(wa.begin(), wa.end(), rng);

            // Variant B: substitution + shuffle
            std::array<int, 10> sub;
            for (int i = 0; i < 10; ++i) sub[i] = i;
            std::shuffle(sub.begin(), sub.end(), rng);
            std::string wb = window;
            for (char& ch : wb) ch = static_cast<char>('0' + sub[ch - '0']);
            std::shuffle(wb.begin(), wb.end(), rng);

            // Attacker's view: histograms of the transformed windows
            Hist ha{}, hb{};
            for (char ch : wa) ++ha[ch - '0'];
            for (char ch : wb) ++hb[ch - '0'];
            const Hist sigB = sortedDesc(hb);

            // Slide across the table
            Hist cur{};
            for (int i = 0; i < w; ++i) ++cur[pi[i] - '0'];
            int matchA = 0, matchB = 0;
            for (int p = 0; p < positions; ++p) {
                if (p > 0) {
                    --cur[pi[p - 1] - '0'];
                    ++cur[pi[p + w - 1] - '0'];
                }
                if (cur == ha) ++matchA;
                if (sortedDesc(cur) == sigB) ++matchB;
            }
            // The true position always matches, so matchA, matchB >= 1.
            survA += 100.0 * matchA / positions;
            survB += 100.0 * matchB / positions;
            bitsA += std::log2(static_cast<double>(positions) / matchA);
            bitsB += std::log2(static_cast<double>(positions) / matchB);
        }

        survA /= TRIALS; survB /= TRIALS; bitsA /= TRIALS; bitsB /= TRIALS;
        std::cout << std::left << std::fixed << std::setw(10) << w
                  << std::setw(15) << std::setprecision(3) << survA
                  << std::setw(15) << std::setprecision(2) << bitsA
                  << std::setw(15) << std::setprecision(3) << survB
                  << std::setprecision(2) << bitsB << "\n";
        csv << w << ",A_shuffle," << survA << "," << bitsA << "\n";
        csv << w << ",B_substitution_shuffle," << survB << "," << bitsB << "\n";
    }
    std::cout << "\nSaved: results_exp2.csv\n";
    std::cout << "Note: this attacker uses ONLY the histogram. Repetition patterns leak more.\n";
}

// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
    int digits = 50000;
    if (argc > 1) digits = std::max(1000, std::atoi(argv[1]));

    std::string pi = loadPiFromFile("pi.txt");
    if (pi.size() >= 1000) {
        std::cout << "Loaded " << pi.size() << " digits of pi from pi.txt\n";
    } else {
        std::cout << "Generating " << digits << " digits of pi (spigot, may take a few seconds)...\n";
        pi = generatePi(digits);
    }
    std::cout << "First digits: " << pi.substr(0, 32) << "\n";

    std::mt19937_64 rng(20260929ULL);   // fixed seed => reproducible results

    experiment1(pi, rng);
    experiment2(pi, rng);

    std::cout << "\nDone.\n";
    return 0;
}
