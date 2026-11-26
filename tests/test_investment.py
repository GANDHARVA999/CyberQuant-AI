from src.api import investment_category

def test_investment_taxonomy_maps_catalogue_actions():
    assert investment_category("Patch internet-facing server") == "Vulnerability patching"
    assert investment_category("Strengthen identity and access controls") == "Identity and access"
    assert investment_category("Improve backup and recovery") == "Backup and recovery"
