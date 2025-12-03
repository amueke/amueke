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
    GiveLinkToUser # <--- NEW: Import the helper function
)

# --- Fixture to Reset State Before Each Test ---
@pytest.fixture(autouse=True)
def reset_state():
    # Clear mutable state
    SYSTEM_STATE["R"].clear()
    SYSTEM_STATE["L"].clear()
    SYSTEM_STATE["holding"].clear() # <--- NEW: Clear the holding relation
    # Reset Users, ensuring "user_A" and "user_B" are always present for identity checks
    SYSTEM_STATE["U"] = {U_OWNER, "user_A", "user_B"}


# --- INVARIANT CHECKS (Section 6 Validation) ---

def test_invariant_3_vault_non_shareability():
    """
    Validation of Invariant 3: Files in the Personal Vault cannot be shared via links.
    """
    # Setup: Define a Vault resource
    vault_item = Resource(id="vault_doc", is_vault=True)
    SYSTEM_STATE["R"]["vault_doc"] = vault_item
    
    # Action/Assertion: Attempt to create a link (share) for the Vault item (Must fail)
    with pytest.raises(PolicyViolation) as excinfo:
        CreateLink(
            u=U_OWNER, 
            target_id="vault_doc", 
            scope="ANYONE", 
            perms={PERM_VIEW},
            state=SYSTEM_STATE
        )
        
    assert "Vault resources cannot be shared" in str(excinfo.value)
    assert len(SYSTEM_STATE["L"]) == 0 


def test_invariant_7_link_state_consistency_on_delete():
    """
    Validation of Invariant 7 (part ii): No link should point to a deleted resource.
    """
    file_id = "report.docx"
    
    # Setup: Create file and two links pointing to it. 
    # NOTE: CreateLink automatically gives possession to U_OWNER, satisfying the possession check.
    SYSTEM_STATE["R"][file_id] = Resource(id=file_id)
    link_a = CreateLink(U_OWNER, file_id, "ANYONE", {PERM_VIEW}, SYSTEM_STATE)
    link_b = CreateLink(U_OWNER, file_id, "ANYONE", {PERM_EDIT}, SYSTEM_STATE)
    
    assert len(SYSTEM_STATE["L"]) == 2

    # Action: Delete the resource
    DeleteResource(U_OWNER, resource_id=file_id, state=SYSTEM_STATE)
    
    # Assertion: Verify the resource is gone and ALL dangling links were garbage collected
    assert file_id not in SYSTEM_STATE["R"]
    assert len(SYSTEM_STATE["L"]) == 0


# --- STATE TRANSITION CHECKS (Section 9 Validation) ---

def test_transition_deleteresource_precondition_check():
    """
    Validation of DeleteResource Precondition: u=u_owner ∨ (edit ∈ TotalPerms).
    """
    file_id = "temp_data.csv"
    user_viewer = "user_A"
    
    SYSTEM_STATE["R"][file_id] = Resource(id=file_id)

    # Setup 1: Grant User_A only VIEW permission
    view_link = CreateLink(U_OWNER, file_id, "SPECIFIC", {PERM_VIEW}, SYSTEM_STATE)
    view_link.recipients.add(user_viewer)
    
    # FIX: User_A must possess the link token to use it (holding relation)
    GiveLinkToUser(user_viewer, view_link.key, SYSTEM_STATE) 
    
    # Pre-Check 1: Confirm TotalPerms is correct (must ONLY have view)
    perms_check_1 = TotalPerms(user_viewer, file_id, SYSTEM_STATE)
    assert perms_check_1 == {PERM_VIEW}, f"Expected {{'{PERM_VIEW}'}}, got {perms_check_1}"
    
    # Action/Assertion 1: Attempt deletion with User_A (Must fail)
    with pytest.raises(PolicyViolation) as excinfo:
        DeleteResource(u=user_viewer, resource_id=file_id, state=SYSTEM_STATE)
        
    assert "edit permission" in str(excinfo.value)
    assert file_id in SYSTEM_STATE["R"] 
    
    # Setup 2: Grant User_A EDIT permission (Permissions are additive)
    edit_link = CreateLink(U_OWNER, file_id, "SPECIFIC", {PERM_EDIT}, SYSTEM_STATE)
    edit_link.recipients.add(user_viewer)
    
    # FIX: User_A must possess the new edit link token
    GiveLinkToUser(user_viewer, edit_link.key, SYSTEM_STATE) 
    
    # Pre-Check 2: Confirm TotalPerms now has both
    perms_check_2 = TotalPerms(user_viewer, file_id, SYSTEM_STATE)
    assert perms_check_2 == {PERM_VIEW, PERM_EDIT}
    
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
    
    # Setup 1: Folder A (Old Parent) - Shared to 'user_guest' with EDIT permission
    SYSTEM_STATE["R"]["Folder_A"] = Resource(id="Folder_A")
    link_A = CreateLink(U_OWNER, "Folder_A", "SPECIFIC", {PERM_EDIT}, SYSTEM_STATE)
    link_A.recipients.add(user_guest)
    # FIX: User_B must possess the link token
    GiveLinkToUser(user_guest, link_A.key, SYSTEM_STATE)
    
    # Setup 2: Folder B (New Parent) - Shared to 'user_guest' with VIEW permission
    SYSTEM_STATE["R"]["Folder_B"] = Resource(id="Folder_B")
    link_B = CreateLink(U_OWNER, "Folder_B", "SPECIFIC", {PERM_VIEW}, SYSTEM_STATE)
    link_B.recipients.add(user_guest)
    # FIX: User_B must possess the link token
    GiveLinkToUser(user_guest, link_B.key, SYSTEM_STATE)
    
    # Setup 3: File Z is initially inside Folder A
    SYSTEM_STATE["R"][file_z_id] = Resource(id=file_z_id, parent_id="Folder_A")

    # Pre-Move Check: Guest user inherits EDIT from Folder A
    perms_before = TotalPerms(user_guest, file_z_id, SYSTEM_STATE)
    assert PERM_EDIT in perms_before 
    assert PERM_VIEW in perms_before
    
    # Action: Move File Z from Folder A to Folder B (Owner is required to move resources)
    MoveResource(U_OWNER, resource_id=file_z_id, new_parent_id="Folder_B", state=SYSTEM_STATE)
    
    # Post-Move Check: Guest user should lose EDIT (Folder A inheritance is gone) and only have VIEW (Folder B inheritance)
    perms_after = TotalPerms(user_guest, file_z_id, SYSTEM_STATE)
    
    # The set should be exactly {view}
    assert perms_after == {PERM_VIEW}, f"Permissions should be only {{'{PERM_VIEW}'}}, but were {perms_after}"
    assert PERM_EDIT not in perms_after 
    assert PERM_VIEW in perms_after
