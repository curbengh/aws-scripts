"""
Create Billing-Alert-Stack
"""

from aws_cdk import Stack
from aws_cdk import aws_budgets as budgets
from constructs import Construct


class main(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        stack_name: str,
        name: str,
        emails: list[str],
        budget_limit: int,
    ) -> None:

        super().__init__(scope, construct_id, stack_name=stack_name)

        subscribers = []
        for email in emails:
            subscribers.append(
                budgets.CfnBudget.SubscriberProperty(
                    subscription_type="EMAIL",
                    address=email,
                )
            )

        budgets.CfnBudget(
            self,
            f"{name}-CfnBudget",
            budget=budgets.CfnBudget.BudgetDataProperty(
                budget_name=f"{name}-MonthlyBudget",
                budget_type="COST",
                time_unit="MONTHLY",
                budget_limit={"unit": "USD", "amount": budget_limit},
            ),
            notifications_with_subscribers=[
                budgets.CfnBudget.NotificationWithSubscribersProperty(
                    notification=budgets.CfnBudget.NotificationProperty(
                        notification_type="ACTUAL",
                        comparison_operator="GREATER_THAN",
                        threshold_type="ABSOLUTE_VALUE",
                        threshold=budget_limit,
                    ),
                    subscribers=subscribers,
                )
            ],
        )
