# test_policy.py - Formal Policy Validation Checks

import pytest
from model import (
    SYSTEM_STATE,
    Resource,
    U_OWNER,
    PERM_EDIT,
    PERM_VIEW,
    PolicyViolation,
    TotalPerms,
    CreateLink,
    DeleteResource,
    MoveResource,
    GiveLinkToUser
)

@pytest.fixture(autouse=True)
def reset_state():
    SYSTEM_STATE["R"].clear()
    SYSTEM_STATE["L"].clear()
    SYSTEM_STATE["holding"].clear()
    SYSTEM_STATE["U"] = {U_OWNER, "user_A", "user_B"}


def test_invariant_3_vault_non_shareability():
    vault_item = Resource(id="vault_doc", is_vault=True)
    SYSTEM_STATE["R"]["vault_doc"] = vault_item

    with pytest.raises(PolicyViolation):
        CreateLink(U_OWNER, "vault_doc", "ANYONE", {PERM_VIEW}, SYSTEM_STATE)

    assert len(SYSTEM_STATE["L"]) == 0


def test_invariant_7_link_state_consistency_on_delete():
    file_id = "report.docx"
    SYSTEM_STATE["R"][file_id] = Resource(id=file_id)

    CreateLink(U_OWNER, file_id, "ANYONE", {PERM_VIEW}, SYSTEM_STATE)
    CreateLink(U_OWNER, file_id, "ANYONE", {PERM_EDIT}, SYSTEM_STATE)

    DeleteResource(U_OWNER, file_id, SYSTEM_STATE)

    assert file_id not in SYSTEM_STATE["R"]
    assert len(SYSTEM_STATE["L"]) == 0


def test_transition_deleteresource_precondition_check():
    file_id = "temp_data.csv"
    user = "user_A"
    SYSTEM_STATE["R"][file_id] = Resource(id=file_id)

    view_link = CreateLink(U_OWNER, file_id, "SPECIFIC", {PERM_VIEW}, SYSTEM_STATE)
    view_link.recipients.add(user)
    GiveLinkToUser(user, view_link.key, SYSTEM_STATE)

    assert TotalPerms(user, file_id, SYSTEM_STATE) == {PERM_VIEW}

    with pytest.raises(PolicyViolation):
        DeleteResource(user, file_id, SYSTEM_STATE)

    edit_link = CreateLink(U_OWNER, file_id, "SPECIFIC", {PERM_EDIT}, SYSTEM_STATE)
    edit_link.recipients.add(user)
    GiveLinkToUser(user, edit_link.key, SYSTEM_STATE)

    assert TotalPerms(user, file_id, SYSTEM_STATE) == {PERM_VIEW, PERM_EDIT}

    DeleteResource(user, file_id, SYSTEM_STATE)
    assert file_id not in SYSTEM_STATE["R"]


def test_transition_moveresource_effect_inheritance_change():
    SYSTEM_STATE["R"]["Folder_A"] = Resource("Folder_A")
    SYSTEM_STATE["R"]["Folder_B"] = Resource("Folder_B")

    link_a = CreateLink(U_OWNER, "Folder_A", "SPECIFIC", {PERM_EDIT}, SYSTEM_STATE)
    link_a.recipients.add("user_B")
    GiveLinkToUser("user_B", link_a.key, SYSTEM_STATE)

    link_b = CreateLink(U_OWNER, "Folder_B", "SPECIFIC", {PERM_VIEW}, SYSTEM_STATE)
    link_b.recipients.add("user_B")
    GiveLinkToUser("user_B", link_b.key, SYSTEM_STATE)

    SYSTEM_STATE["R"]["file_z"] = Resource("file_z", parent_id="Folder_A")

    assert PERM_EDIT in TotalPerms("user_B", "file_z", SYSTEM_STATE)

    MoveResource(U_OWNER, "file_z", "Folder_B", SYSTEM_STATE)

    assert TotalPerms("user_B", "file_z", SYSTEM_STATE) == {PERM_VIEW}
