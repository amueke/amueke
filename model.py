import uuid
from typing import Dict, Set, Any

# --- Entity Definitions and Constants ---

U_OWNER = "u_owner"
PERM_VIEW = "view"
PERM_EDIT = "edit"

class Resource:
    """Represents R_files and R_folders."""
    def __init__(self, id: str, is_vault: bool = False, parent_id: str = None):
        self.id = id
        self.is_vault = is_vault
        self.parent_id = parent_id 

class Link:
    """Represents a sharing token l in L (Section 4.4)."""
    # SYNTAX FIX: Removed external text from the __init__ signature
    def __init__(self, key: str, target_id: str, perms: Set[str], scope: str = "ANYONE"):
        self.key = key
        self.target_id = target_id
        self.perms = perms 
        self.scope = scope
        self.recipients: Set[str] = set()

# --- Global System State (Γ) ---

SYSTEM_STATE = {
    "R": {},    # {id: Resource} dictionary
    "L": {},    # {key: Link} dictionary
    "U": {U_OWNER}, # Set of users
}

# --- Utility Functions (Relations and Predicates) ---

def req(action: str) -> str:
    """Implements req: A -> P (Section 4.3.1)"""
    # edit subsumes view
    if action in ["edit", "delete", "share"]:
        return PERM_EDIT
    if action in ["view", "download"]:
        return PERM_VIEW
    raise ValueError(f"Unknown action: {action}")

def is_ancestor(ancestor_id: str, resource_id: str, state: Dict) -> bool:
    """Implements is_ancestor(p,c) (Section 5.2)"""
    resource = state["R"].get(resource_id)
    if not resource: return False
    
    current_parent_id = resource.parent_id
    while current_parent_id:
        if current_parent_id == ancestor_id:
            return True
        parent_resource = state["R"].get(current_parent_id)
        if not parent_resource:
            break
        current_parent_id = parent_resource.parent_id
    return False

def ValidLink(link: Link, user: str, state: Dict, action: str = PERM_VIEW) -> bool:
    """
    Simplified implementation of ValidLink(l, u, a, Γ) (Section 7.2).
    Checks Identity and Permissions.
    """
    
    # 2. Identity: ((l.scope = ANYONE) V (u ∈ recipients(l)))
    if link.scope == "SPECIFIC" and user not in link.recipients:
        return False

    # 5. Permissions: (req(a) ∈ l.perms_effective)
    required_perm = req(action)
    
    # Check if the required permission is granted by the link's explicit permissions (Pl)
    if required_perm in link.perms:
        return True
    
    # Check if a higher permission grants the required one (edit subsumes view)
    if required_perm == PERM_VIEW and PERM_EDIT in link.perms:
        return True
        
    return False

def TotalPerms(user: str, resource_id: str, state: Dict, context: Dict = {}) -> Set[str]:
    """
    Implements TotalPerms(u, r, Γ) (Section 7.4). 
    Fixes: Ensures ValidLink (Identity/Possession) check is performed.
    """
    
    effective_perms = set()

    # Owner has implicit, irrevocable full control
    if user == U_OWNER:
        return {PERM_VIEW, PERM_EDIT}

    # Iterate through all active links (L)
    for link_key, link in state["L"].items():
        
        # Check if the link is even usable by the user (Identity/Possession)
        if not ValidLink(link, user, state, action=PERM_VIEW):
            continue

        # Direct Perms: l.target = r
        if link.target_id == resource_id:
            effective_perms.update(link.perms)
            
        # Inherited Perms: is_ancestor(l.target, r)
        if is_ancestor(link.target_id, resource_id, state):
            effective_perms.update(link.perms)
            
    # TotalPerms is the union of all permissions
    return effective_perms

# --- Operational Semantics (Section 9) ---

class PolicyViolation(Exception):
    """Custom exception for policy precondition failures."""
    pass

def generate_key():
    """Generates a unique link key (Invariant 8: Key Uniqueness)"""
    return str(uuid.uuid4())

def CreateLink(u: str, target_id: str, scope: str, perms: Set[str], state: Dict, context: Dict = {}):
    """Implements CreateLink (Section 9.1)"""
    
    target_resource = state["R"].get(target_id)
    if not target_resource:
        raise PolicyViolation("Target resource does not exist.")

    # Precondition: (u=u_owner V edit in TotalPerms) AND target not in R_vault
    has_edit_perm = PERM_EDIT in TotalPerms(u, target_id, state, context)
    
    if target_resource.is_vault:
        # Invariant 3: Vault Non-Shareability
        raise PolicyViolation("Vault resources cannot be shared via links (Invariant 3).")
        
    if u != U_OWNER and not has_edit_perm:
        raise PolicyViolation("Only the owner or users with edit permission can create links.")

    # Effect: Create new link
    new_key = generate_key()
    new_link = Link(key=new_key, target_id=target_id, perms=perms, scope=scope)
    state["L"][new_key] = new_link
    return new_link

def DeleteResource(u: str, resource_id: str, state: Dict, context: Dict = {}):
    """Implements DeleteResource (Section 9.7)"""

    # Precondition: u=u_owner(resource) ∨ (edit ∈ TotalPerms)
    if u != U_OWNER and PERM_EDIT not in TotalPerms(u, resource_id, state, context):
        raise PolicyViolation("Deletion requires owner status or explicit edit permission.")

    # Effect 1: R' = R \ {resource}
    if resource_id in state["R"]:
        del state["R"][resource_id]

    # Effect 2: Garbage collection of dangling links (Invariant 7 - part ii)
    links_to_keep = {}
    for key, link in state["L"].items():
        if link.target_id != resource_id:
            links_to_keep[key] = link
    state["L"] = links_to_keep

def MoveResource(u: str, resource_id: str, new_parent_id: str, state: Dict, context: Dict = {}):
    """Implements MoveResource (Section 9.6)"""
    
    # Precondition: Owner required (implied in formal model for state transitions)
    if u != U_OWNER:
        raise PolicyViolation("Only the owner can move resources.")

    resource = state["R"].get(resource_id)
    new_parent = state["R"].get(new_parent_id)

    if not resource or not new_parent:
        raise PolicyViolation("Resource or new parent not found.")
    
    # Check for Acyclic Hierarchy (Invariant 2)
    if is_ancestor(resource_id, new_parent_id, state):
         raise PolicyViolation("Cannot move a resource into its own descendant (Acyclic Hierarchy Violation).")


    # Effect: parent'(resource) = new_parent
    resource.parent_id = new_parent_id
    # Result: Permissions change implicitly via TotalPerms
