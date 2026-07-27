"""TerraGuard-AI: Terraform drift, state-handling and policy-control analysis with ML ranking.

Design rule enforced throughout this package: detection is deterministic, ranking is learned.
No model output may decide whether drift exists or whether a control was violated.
"""

__version__ = "0.1.0"
