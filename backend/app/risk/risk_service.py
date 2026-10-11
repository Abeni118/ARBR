from app.risk.risk_engine import RiskAssessment, RiskEngine, RiskEvent


class RiskService:
    def __init__(self, engine: RiskEngine | None = None):
        self.engine = engine or RiskEngine()

    def assess(
        self,
        event_id: str,
        host_id: str,
        indicators: dict[str, bool],
    ) -> RiskAssessment:
        event = RiskEvent(
            event_id=event_id,
            host_id=host_id,
            indicators=indicators,
        )

        return self.engine.assess(event)