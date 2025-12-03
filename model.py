import uuid
from typing import Dict, Set, Any, List

# --- Entity Definitions and Constants (Section 4) ---

U_OWNER = "u_owner"
PERM_VIEW = "view"
PERM_EDIT = "edit"
PERMISSION_SET = {PERM_VIEW, PERM_EDIT}

class Resource:
    """Represents R_files and R_folders."""
    def __init__(self, id: str, is_vault: bool = False, parent_id: str = None):
        self.id = id
        self.is_vault = is_vault
        self.parent_id = parent_id # Implements parent: R\{root} -> Rfolders

class Link:
    """Represents a sharing token l in L."""
    def __init__(self, key: str, target_id: str, perms: Set[str], scope: str = "ANYONE"):
        self.key = key
        self.target_id = target_id
        self.perms = perms # e.g., {"view"}, {"view", "edit"}
        self.scope = scope
        self.recipients: Set[str] = set() # Implements recipients: L -> P(U)

# --- Global System State (Γ) ---

SYSTEM_STATE = {
    "R": {},    # {id: Resource} dictionary
    "L": {},    # {key: Link} dictionary
    "U": {U_OWNER}, # Set of users
}

# --- Utility Functions (Relations and Predicates) ---

def req(action: str) -> str:
    """Implements req: A -> P (Section 4.3.1)"""
    # edit subsumes view (edit grants view and download)
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

def ValidLink(link: Link, user: str, action: str, state: Dict, context: Dict = {}) -> bool:
    """Implements ValidLink(l, u, a, Γ) (Section 7.2) - Simplified Context Check"""
    
    # 1. Possession: (u, l) ∈ holding (Simplified: assuming link key is known)
    # In a real system, you'd check if 'user' has possession of 'link.key'.
    # For testing, we assume possession if the user is in the recipient list or it's an ANYONE link.
    
    # 2. Identity: (l.scope = ANYONE) V (u ∈ recipients(l))
    if link.scope == "SPECIFIC" and user not in link.recipients:
        return False

    # 5. Permissions: (req(a) ∈ l.perms_effective)
    required = req(action)
    if required not in link.perms:
        return False

    # Simplified checks for Expiration, Password, etc. are omitted for brevity in this example.
    return True

def TotalPerms(user: str, resource_id: str, state: Dict, context: Dict = {}) -> Set[str]:
    """Implements TotalPerms(u, r, Γ) (Section 7.4)"""
    
    effective_perms = set()

    # Owner has implicit, irrevocable full control
    if user == U_OWNER:
        return {PERM_VIEW, PERM_EDIT}

    # Iterate through all active links (L)
    for link_key, link in state["L"].items():
        # Check Direct Perms
        if link.target_id == resource_id and ValidLink(link, user, PERM_VIEW, state, context):
            effective_perms.update(link.perms)
            
        # Check Inherited Perms
        if is_ancestor(link.target_id, resource_id, state) and ValidLink(link, user, PERM_VIEW, state, context):
            effective_perms.update(link.perms)
            
    # Combined Permission Evaluation: effective access is the union of all permissions
    return effective_perms

# --- Operational Semantics (Section 9) ---

class PolicyViolation(Exception):
    """Custom exception for policy precondition failures."""
    pass

def generate_key():
    """Generates a unique link key (Invariant 8: Key Uniqueness)"""
    return str(uuid.uuid4())

def CreateLink(u: str, target_id: str, scope: str, perms: Set[str], state: Dict, context: Dict = {}):
    """Implements CreateLink(u, target, scope, perms, constraints) (Section 9.1)"""
    
    target_resource = state["R"].get(target_id)
    if not target_resource:
        raise PolicyViolation("Target resource does not exist.")

    # Precondition (Section 9.1): (u=u_owner V edit ∈ TotalPerms) ∧ target ∉ R_vault
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
    """Implements DeleteResource(u, resource) (Section 9.7)"""

    # Precondition (Section 9.7): u=u_owner(resource) ∨ (edit ∈ TotalPerms(u, resource, Γ))
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
    """Implements MoveResource(owner, resource, new_parent) (Section 9.6)"""
    
    # Precondition (Simplified): Only owner can move resources
    if u != U_OWNER:
        raise PolicyViolation("Only the owner can move resources.")

    resource = state["R"].get(resource_id)
    new_parent = state["R"].get(new_parent_id)

    if not resource or not new_parent:
        raise PolicyViolation("Resource or new parent not found.")
    
    # Check for Acyclic Hierarchy (Invariant 2 - Prevent moving a parent into a child)
    if is_ancestor(resource_id, new_parent_id, state):
         raise PolicyViolation("Cannot move a resource into its own descendant (Acyclic Hierarchy Violation).")


    # Effect: parent'(resource) = new_parent
    resource.parent_id = new_parent_id
    # Result: The effective permissions for the resource change implicitly via TotalPerms
