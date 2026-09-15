from dataclasses import dataclass

@dataclass
class Finding:
    name: str
    description: str
    risk_level: str  # "Very Risky", "Risky", "Medium", "Low"

class RiskEngine:
    # Mapping risk levels to the user's requested colors
    COLORS = {
        "Very Risky": "red",
        "Risky": "magenta",  # Pink
        "Medium": "yellow",
        "Low": "cyan",       # Light Blue
    }

    @staticmethod
    def get_color(level):
        return RiskEngine.COLORS.get(level, "white")
