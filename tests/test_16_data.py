def test_data(client, module, slot):
    params = {"label": "datatest", "objtype": "DATA", "data": "string=="}
    assert (
        len(client.post(f"/hsm/{module}/{slot}/import", json=params).json()["objects"])
        > 0
    )
