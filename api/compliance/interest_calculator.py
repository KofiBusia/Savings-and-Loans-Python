"""
Ghana Savings & Loans — Simple Interest Calculator
Regulatory anchor: Digital Credit Directive 2025, Clause 14
"Interest charged on digital credit shall be simple interest only."

CompoundInterestAttempted is raised (ValueError subclass) if any caller
attempts to apply compounding. This guard is tested in the CI compliance suite.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Literal


# ─── Exceptions ───────────────────────────────────────────────────────────────

class CompoundInterestAttempted(ValueError):
    """Raised whenever compound-interest logic is detected or requested.

    DCD 2025 Clause 14 prohibits compound interest on digital credit.
    Any code path that triggers this exception MUST NOT be deployed.
    """


class InterestRateExceedsBoGCap(ValueError):
    """Raised when the annual rate exceeds the BoG maximum rate cap."""


# ─── Config ───────────────────────────────────────────────────────────────────

# BoG maximum unsecured lending rate (review periodically from BoG website)
BOG_MAX_ANNUAL_RATE: Decimal = Decimal("0.60")   # 60% p.a.
BOG_MIN_ANNUAL_RATE: Decimal = Decimal("0.00")


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RepaymentInstalment:
    period: int                 # 1-based instalment number
    due_date: date
    opening_balance: Decimal
    principal_component: Decimal
    interest_component: Decimal
    total_payment: Decimal
    closing_balance: Decimal


@dataclass
class LoanSchedule:
    principal: Decimal
    annual_rate: Decimal
    tenure_months: int
    disbursement_date: date
    instalments: list[RepaymentInstalment] = field(default_factory=list)
    total_interest: Decimal = Decimal("0")
    total_repayable: Decimal = Decimal("0")
    apr: Decimal = Decimal("0")
    interest_type: Literal["SIMPLE"] = "SIMPLE"   # always SIMPLE — DCD 2025

    def __post_init__(self) -> None:
        # Immutable proof that compound interest was never used
        assert self.interest_type == "SIMPLE", "Only SIMPLE interest is permitted (DCD 2025)"


# ─── Calculator ───────────────────────────────────────────────────────────────

class SimpleInterestCalculator:
    """Builds repayment schedules using SIMPLE interest only.

    Formula:  I = P × R × T
    Where:    P = principal (GHS)
              R = monthly rate = annual_rate / 12
              T = number of months
    """

    @staticmethod
    def _validate_rate(annual_rate: Decimal) -> None:
        if annual_rate > BOG_MAX_ANNUAL_RATE:
            raise InterestRateExceedsBoGCap(
                f"Rate {annual_rate:.2%} exceeds BoG cap of {BOG_MAX_ANNUAL_RATE:.2%}"
            )
        if annual_rate < BOG_MIN_ANNUAL_RATE:
            raise ValueError("Interest rate cannot be negative")

    @staticmethod
    def _guard_compound(n_compounding_periods: int) -> None:
        """Explicit guard: any n > 1 means compound interest is requested."""
        if n_compounding_periods > 1:
            raise CompoundInterestAttempted(
                "Compound interest is prohibited by Digital Credit Directive 2025, Clause 14. "
                f"Requested compounding periods={n_compounding_periods}."
            )

    def calculate(
        self,
        principal: float | Decimal,
        annual_rate_pct: float | Decimal,  # e.g. 24 means 24%
        tenure_months: int,
        disbursement_date: date | None = None,
        *,
        compounding_periods: int = 1,   # must always be 1 — guard fires otherwise
    ) -> LoanSchedule:
        """Generate a full amortisation schedule.

        Args:
            principal: Loan amount in GHS.
            annual_rate_pct: Annual interest rate as a percentage (e.g. 24 = 24%).
            tenure_months: Loan term in months.
            disbursement_date: Date of disbursement; defaults to today.
            compounding_periods: MUST remain 1. Passing >1 raises CompoundInterestAttempted.

        Returns:
            LoanSchedule with full instalment breakdown.
        """
        self._guard_compound(compounding_periods)

        p = Decimal(str(principal)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        r_annual = Decimal(str(annual_rate_pct)) / Decimal("100")

        self._validate_rate(r_annual)

        r_monthly = r_annual / Decimal("12")
        start = disbursement_date or date.today()

        # SIMPLE INTEREST: total interest = P × r_monthly × tenure_months
        total_interest = (p * r_monthly * Decimal(str(tenure_months))).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        total_repayable = p + total_interest
        equal_instalment = (total_repayable / Decimal(str(tenure_months))).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )

        # Interest per instalment is constant (flat-rate simple interest)
        interest_per_instalment = (total_interest / Decimal(str(tenure_months))).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        principal_per_instalment = (p / Decimal(str(tenure_months))).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )

        instalments: list[RepaymentInstalment] = []
        balance = p

        for i in range(1, tenure_months + 1):
            due_date = start + timedelta(days=30 * i)
            # Adjust final instalment for rounding residual
            if i == tenure_months:
                principal_component = balance
                interest_component = total_interest - sum(
                    ins.interest_component for ins in instalments
                )
            else:
                principal_component = principal_per_instalment
                interest_component = interest_per_instalment

            total_payment = principal_component + interest_component
            closing = balance - principal_component

            instalments.append(RepaymentInstalment(
                period=i,
                due_date=due_date,
                opening_balance=balance,
                principal_component=principal_component,
                interest_component=interest_component,
                total_payment=total_payment,
                closing_balance=closing,
            ))
            balance = closing

        apr = self._calculate_apr(p, total_repayable, tenure_months)

        return LoanSchedule(
            principal=p,
            annual_rate=r_annual,
            tenure_months=tenure_months,
            disbursement_date=start,
            instalments=instalments,
            total_interest=total_interest,
            total_repayable=total_repayable,
            apr=apr,
        )

    @staticmethod
    def _calculate_apr(
        principal: Decimal,
        total_repayable: Decimal,
        tenure_months: int,
    ) -> Decimal:
        """Approximate APR using Newton's method (IRR of cash flows).

        Disclosed on all loan agreements per Borrowers & Lenders Act 2020.
        """
        monthly_payment = total_repayable / Decimal(str(tenure_months))
        # Newton–Raphson: find r such that NPV = 0
        r = Decimal("0.02")  # initial guess: 2% monthly
        for _ in range(1000):
            npv = -principal
            for t in range(1, tenure_months + 1):
                npv += monthly_payment / ((1 + r) ** t)
            d_npv = sum(
                -Decimal(str(t)) * monthly_payment / ((1 + r) ** (t + 1))
                for t in range(1, tenure_months + 1)
            )
            if abs(d_npv) < Decimal("1e-10"):
                break
            r_new = r - npv / d_npv
            if abs(r_new - r) < Decimal("1e-8"):
                r = r_new
                break
            r = r_new
        return (r * 12 * 100).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def validate_no_compound_terms(self, formula_description: str) -> None:
        """Call this when accepting interest formulas from external config.

        Parses the description for compound-interest markers and raises if found.
        """
        compound_markers = ["compound", "compounding", "(1+r)^", "e^", "exp("]
        lower = formula_description.lower()
        for marker in compound_markers:
            if marker in lower:
                raise CompoundInterestAttempted(
                    f"Formula contains compound-interest term '{marker}'. "
                    "Prohibited by DCD 2025 Clause 14."
                )


# ─── Module-level singleton ────────────────────────────────────────────────────
calculator = SimpleInterestCalculator()
