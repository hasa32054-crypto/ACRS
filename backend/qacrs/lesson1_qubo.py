"""Lesson 1: what a QUBO is, on the smallest real ACRS decision.  (pure Python, runs anywhere)

    python3 -m qacrs.lesson1_qubo

Three hacked machines:
  A, B : the two servers behind the appointments website (twins: the site works if at least one serves)
  C    : an ordinary office PC

One yes/no decision per machine:   x = 1 -> isolate it fully      x = 0 -> only restrict it (block the attacker's IP)

The numbers below are TEACHING NUMBERS, chosen to make the idea visible. They are not results.
"""
from itertools import product

MACHINES = ["A (web twin 1)", "B (web twin 2)", "C (office PC)"]
LEFTOVER_RISK = [3, 3, 4]   # risk that remains if we only restrict (x=0) instead of isolating
DISRUPTION = [1, 1, 1]      # cost of taking that machine offline (x=1)
SITE_DOWN = 20              # extra cost if A AND B are both offline: the website stops


def cost(x):
    c = 0
    for i in range(3):
        c += LEFTOVER_RISK[i] * (1 - x[i])   # restrict only -> some risk left
        c += DISRUPTION[i] * x[i]            # isolate -> that machine is down
    c += SITE_DOWN * x[0] * x[1]             # the quadratic term: the two twins together
    return c


def main():
    print("Every possible decision (2^3 = 8):\n")
    print(f"{'A':>3}{'B':>3}{'C':>3}   cost   meaning")
    rows = []
    for x in product([0, 1], repeat=3):
        meaning = ", ".join(f"{'isolate' if v else 'restrict'} {m.split()[0]}" for v, m in zip(x, MACHINES))
        rows.append((cost(x), x, meaning))
    for c, x, m in sorted(rows):
        star = "  <- best" if c == min(r[0] for r in rows) else ""
        print(f"{x[0]:>3}{x[1]:>3}{x[2]:>3}   {c:>4}   {m}{star}")
    print("\nThe x_A * x_B term is what makes this 'Quadratic': it lets the model see that isolating BOTH")
    print("twins kills the website, something a per-machine rule cannot see.")


if __name__ == "__main__":
    main()
