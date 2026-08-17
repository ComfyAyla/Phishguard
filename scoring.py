# scoring.py
# Calculates aggregate threat points from triggered indicators and determines the RiskLevel.

from typing import List
from models import Indicator, RiskResult, RiskLevel, logger

# Scoring thresholds for risk categorization
HIGH_RISK_THRESHOLD = 25
MEDIUM_RISK_THRESHOLD = 10

def calculate_risk(indicators: List[Indicator], whitelisted: bool = False) -> RiskResult:
    """
    Calculates the total risk score and maps it to a RiskLevel (LOW, MEDIUM, HIGH).
    If the sender is whitelisted, overrides risk to LOW with 0 points.
    """
    if whitelisted:
        logger.info("Sender is on whitelist. Skipping threat scoring and overriding risk to LOW.")
        return RiskResult(score=0, level=RiskLevel.LOW, indicators=[])
        
    total_score = sum(ind.points for ind in indicators)
    
    if total_score >= HIGH_RISK_THRESHOLD:
        level = RiskLevel.HIGH
    elif total_score >= MEDIUM_RISK_THRESHOLD:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW
        
    logger.debug(f"Risk calculation completed: Score={total_score}, Level={level}, IndicatorsCount={len(indicators)}")
    return RiskResult(score=total_score, level=level, indicators=indicators)