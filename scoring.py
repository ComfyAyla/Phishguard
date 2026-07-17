# phishguard/scoring.py (or scoring.py)
from typing import List
from models import Indicator, RiskLevel, RiskResult

# Define clear, configurable scoring thresholds
THRESHOLD_MEDIUM = 20
THRESHOLD_HIGH = 50

def calculate_risk(indicators: List[Indicator]) -> RiskResult:
    """
    Sums the risk points from all triggered indicators and 
    determines the overall RiskLevel classification.
    """
    # 1. Sum up all indicator points
    total_score = sum(ind.points for ind in indicators)
    
    # 2. Classify based on thresholds
    if total_score >= THRESHOLD_HIGH:
        level = RiskLevel.HIGH
    elif total_score >= THRESHOLD_MEDIUM:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
        
    # 3. Return the populated RiskResult object
    return RiskResult(
        score=total_score,
        level=level,
        indicators=indicators
    )