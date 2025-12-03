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
    def __init__(self, key: str, target_id: str, perms: Set[str], scope: str = "ANYONE"):
        self.key = key
        self.target_id = target_id
        self.perms = perms
        self.scope = scope
        self.recipients: Set[str] = set()

# --- Global System State (Γ) ---

SYSTEM_STATE = {
    "R": {},          # {id: Resource}
    "L": {},          # {key: Link}
    "U": {U_OWNER},   # users
}

# --- Utility Functions ---

def req(action: str) -> str:
    """Map actions to required permission."""
    if action in ["edit", "delete", "share"]:
        return PERM_EDIT
    if action in ["view", "download"]:
        return PERM_VIEW
    raise ValueError(f"Unknown action: {action}")

def is_ancestor(ancestor_id: str, resource_id: str, state: Dict) -> bool:
    """Check whether ancestor_id is an ancestor of resource_id."""
    resource = state["R"].get(resource_id)
    if not resource:
        return False

    pid = resource.parent_id
    while pid:
        if pid == ancestor_id:
            return True
        parent = state["R"].get(pid)
        if not parent:
            break
        pid = parent.parent_id

    return False

def ValidLink(link: Link, user: str, state: Dict, act: str = "view") -> bool:
    """Check if link is valid for user and action."""
    # Identity condition
    if link.scope == "SPECIFIC" and user not in link.recipients:
        return False

    required_perm = req(act)

    # Direct match
    if required_perm in link.perms:
        return True

    # Subsumption: edit grants view
    if required_perm == PERM_VIEW and PERM_EDIT in link.perms:
        return True

    return False

def TotalPerms(user: str, resource_id: str, state: Dict, context: Dict = {}) -> Set[str]:
    """Compute effective permissions."""
    effective = set()

    # owner always has full rights
    if user == U_OWNER:
        return {PERM_VIEW, PERM_EDIT}

    for k, link in state["L"].items():
        if not ValidLink(link, user, state, act="view"):
            continue

        # direct target
        if link.target_id == resource_id:
            effective.update(link.perms)

        # inherited from ancestors
        if is_ancestor(link.target_id, resource_id, state):
            effective.update(link.perms)

    # Subsumption (required by tests): EDIT implies VIEW
    if PERM_EDIT in effective:
        effective.add(PERM_VIEW)

    return effective

# --- Operational Semantics ---

class PolicyViolation(Exception):
    pass

def generate_key():
    return str(uuid.uuid4())

def CreateLink(u: str, target_id: str, scope: str, perms: Set[str], state: Dict, context: Dict = {}):
    """CreateLink transition."""
    target = state["R"].get(target_id)
    if not target:
        raise PolicyViolation("Target resource does not exist.")

    has_edit = PERM_EDIT in TotalPerms(u, target_id, state, context)

    if target.is_vault:
        raise PolicyViolation("Vault resources cannot be shared via links.")

    if u != U_OWNER and not has_edit:
        raise PolicyViolation("Only owner or users with edit permission can create links.")

    key = generate_key()
    link = Link(key=key, target_id=target_id, perms=perms, scope=scope)
    state["L"][key] = link
    return link

def DeleteResource(u: str, resource_id: str, state: Dict, context: Dict = {}):
    """DeleteResource transition."""
    if u != U_OWNER and PERM_EDIT not in TotalPerms(u, resource_id, state, context):
        raise PolicyViolation("Deletion requires edit permission.")

    # delete resource
    if resource_id in state["R"]:
        del state["R"][resource_id]

    # garbage collect dangling links
    state["L"] = {k: l for k, l in state["L"].items() if l.target_id != resource_id}

def MoveResource(u: str, resource_id: str, new_parent_id: str, state: Dict, context: Dict = {}):
    """MoveResource transition."""
    if u != U_OWNER:
        raise PolicyViolation("Only owner can move resources.")

    res = state["R"].get(resource_id)
    np = state["R"].get(new_parent_id)

    if not res or not np:
        raise PolicyViolation("Resource or parent not found.")

    if is_ancestor(resource_id, new_parent_id, state):
        raise PolicyViolation("Cannot move a resource into its own descendant.")

    res.parent_id = new_parent_id
