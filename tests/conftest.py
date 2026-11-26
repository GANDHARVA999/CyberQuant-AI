import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(scope="session")
def fast_classifier():
    """A smaller forest trained on fewer simulated sessions: enough for behaviour tests, quick to build."""
    from src.engine.model import Classifier, train
    return Classifier.from_model(train(train_seeds=range(14), test_seeds=range(1000, 1003), save=False)["_model"])
