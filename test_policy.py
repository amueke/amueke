# test_policy.py

import pytest
from model import (
    SYSTEM_STATE,
    Resource,
    Link,
    U_OWNER,
    PERM_EDIT,
    PERM_VIEW,
    PolicyViolation,
    TotalPerms,
    CreateLink,
    DeleteResource,
    MoveResource
)

# --- Fixture to Reset State Before Each Test ---
# Ensures tests are independent by resetting the global state
@pytest.fixture(autouse=True)
def reset_state():
    SYSTEM_STATE["R"].clear()
    SYSTEM_STATE["L"].clear()
    SYSTEM_STATE["U"] = {U_OWNER, "user_A", "user_B"}


# --- INVARIANT CHECKS (Section 6 Validation) ---

def test_invariant_3_vault_non_shareability():
    """
    Validation of Invariant 3: Files in the Personal Vault cannot be shared via links.
    This check ensures the CreateLink precondition rejects R_vault targets.
    """
    # Setup: Define a Vault resource
    vault_item = Resource(id="vault_doc", is_vault=True)
    SYSTEM_STATE["R"]["vault_doc"] = vault_item
    
    # Action/Assertion: Attempt to create a link (share) for the Vault item
    with pytest.raises(PolicyViolation) as excinfo:
        CreateLink(
            u=U_OWNER, 
            target_id="vault_doc", 
            scope="ANYONE", 
            perms={PERM_VIEW},
            state=SYSTEM_STATE
        )
        
    # Check for correct error message
    assert "Vault resources cannot be shared" in str(excinfo.value)
    
    # Assert Invariant 3: No new link should exist
    assert len(SYSTEM_STATE["L"]) == 0 


def test_invariant_7_link_state_consistency_on_delete():
    """
    Validation of Invariant 7 (part ii): No user can 'hold' a link that does not exist.
    This check ensures the garbage collection effect of DeleteResource is correctly implemented.
    """
    file_id = "report.docx"
    
    # Setup: Create file and two links pointing to it
    SYSTEM_STATE["R"][file_id] = Resource(id=file_id)
    link_a = CreateLink(U_OWNER, file_id, "ANYONE", {PERM_VIEW}, SYSTEM_STATE)
    link_b = CreateLink(U_OWNER, file_id, "ANYONE", {PERM_EDIT}, SYSTEM_STATE)
    
    initial_link_count = len(SYSTEM_STATE["L"]) 
    assert initial_link_count == 2

    # Action: Delete the resource
    DeleteResource(U_OWNER, resource_id=file_id, state=SYSTEM_STATE)
    
    # Assertion: Verify the resource is gone and ALL dangling links were garbage collected
    assert file_id not in SYSTEM_STATE["R"]
    assert len(SYSTEM_STATE["L"]) == 0
    assert link_a.key not in SYSTEM_STATE["L"]
    assert link_b.key not in SYSTEM_STATE["L"]


# --- STATE TRANSITION CHECKS (Section 9 Validation) ---

def test_transition_deleteresource_precondition_check():
    """
    Validation of DeleteResource Precondition: u=u_owner ∨ (edit ∈ TotalPerms).
    A user with only VIEW permission must be denied deletion.
    """
    file_id = "temp_data.csv"
    user_viewer = "user_A"
    SYSTEM_STATE["R"][file_id] = Resource(id=file_id)

    # Setup: Grant User_A only VIEW permission
    CreateLink(U_OWNER, file_id, "SPECIFIC", {PERM_VIEW}, SYSTEM_STATE).recipients.add(user_viewer)
    
    # Pre-Check: Confirm TotalPerms is correct (should only have view)
    assert TotalPerms(user_viewer, file_id, SYSTEM_STATE) == {PERM_VIEW}
    
    # Action/Assertion 1: Attempt deletion with User_A (Must fail)
    with pytest.raises(PolicyViolation) as excinfo:
        DeleteResource(u=user_viewer, resource_id=file_id, state=SYSTEM_STATE)
        
    assert "edit permission" in str(excinfo.value)
    # Post-Condition Check: The file must still exist
    assert file_id in SYSTEM_STATE["R"] 
    
    # Setup 2: Grant User_A EDIT permission (e.g., via a new link)
    CreateLink(U_OWNER, file_id, "SPECIFIC", {PERM_EDIT}, SYSTEM_STATE).recipients.add(user_viewer)
    assert TotalPerms(user_viewer, file_id, SYSTEM_STATE) == {PERM_VIEW, PERM_EDIT}
    
    # Action/Assertion 2: Attempt deletion with User_A (Must succeed)
    DeleteResource(u=user_viewer, resource_id=file_id, state=SYSTEM_STATE)
    
    # Post-Condition Check: The file must now be gone
    assert file_id not in SYSTEM_STATE["R"]


def test_transition_moveresource_effect_inheritance_change():
    """
    Validation of MoveResource Effect: Resource loses old inheritance, gains new.
    """
    file_z_id = "file_z"
    user_guest = "user_B"
    
    # Setup 1: Folder A (Parent) - Shared EDIT
    SYSTEM_STATE["R"]["Folder_A"] = Resource(id="Folder_A")
    CreateLink(U_OWNER, "Folder_A", "SPECIFIC", {PERM_EDIT}, SYSTEM_STATE).recipients.add(user_guest)
    
    # Setup 2: Folder B (New Parent) - Shared VIEW
    SYSTEM_STATE["R"]["Folder_B"] = Resource(id="Folder_B")
    CreateLink(U_OWNER, "Folder_B", "SPECIFIC", {PERM_VIEW}, SYSTEM_STATE).recipients.add(user_guest)
    
    # Setup 3: File Z is initially inside Folder A
    SYSTEM_STATE["R"][file_z_id] = Resource(id=file_z_id, parent_id="Folder_A")

    # Pre-Move Check: Guest user inherits EDIT from Folder A
    perms_before = TotalPerms(user_guest, file_z_id, SYSTEM_STATE)
    assert PERM_EDIT in perms_before 
    assert PERM_VIEW in perms_before
    
    # Action: Move File Z from Folder A to Folder B
    MoveResource(U_OWNER, resource_id=file_z_id, new_parent_id="Folder_B", state=SYSTEM_STATE)
    
    # Post-Move Check: Guest user should lose EDIT and only have VIEW from Folder B
    perms_after = TotalPerms(user_guest, file_z_id, SYSTEM_STATE)
    assert PERM_EDIT not in perms_after 
    assert PERM_VIEW in perms_after
