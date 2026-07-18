from app.models.deception_campaign import DeceptionCampaign


def test_model_has_expected_columns():
    cols = set(DeceptionCampaign.__table__.columns.keys())
    assert {"id", "client_id", "name", "config", "status", "created_at"} <= cols


def test_model_tablename():
    assert DeceptionCampaign.__tablename__ == "deception_campaigns"


def test_status_default_is_pending():
    col = DeceptionCampaign.__table__.columns["status"]
    assert col.default.arg == "pending"
