from typing import List
from models import Indicator, RiskLevel, RiskResult

THRESHOLD_MEDIUM = 20
THRESHOLD_HIGH = 50

def calculate_risk(indicators: List[Indicator], whitelisted: bool = False) -> RiskResult:
    """
    Sums risk points and determines the RiskLevel. 
    Bypasses and returns a clean result if whitelisted is True.
    """
    if whitelisted:
        return RiskResult(
            score=0,
            level=RiskLevel.LOW,
            indicators=[Indicator(
                name="WHITELISTED_SENDER", 
                points=0, 
                description="This sender or domain is on your local Whitelist."
            )]
        )

    total_score = sum(ind.points for ind in indicators)
    
    if total_score >= THRESHOLD_HIGH:
        level = RiskLevel.HIGH
    elif total_score >= THRESHOLD_MEDIUM:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
        
    return RiskResult(
        score=total_score,
        level=level,
        indicators=indicators
    )
