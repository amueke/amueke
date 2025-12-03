import uuid
from typing import Dict, Set, Any

# ---------------------- CONSTANTS ----------------------

U_OWNER = "u_owner"
PERM_VIEW = "view"
PERM_EDIT = "edit"

ACTIONS_THAT_MAP_TO_EDIT = {"edit", "delete", "share"}
ACTIONS_THAT_MAP_TO_VIEW = {"view", "download"}

# ---------------------- ENTITIES ------------------------

class Resource:
    """Represents files/folders."""
    def __init__(self, id: str, is_vault: bool = False, parent_id: str = None):
        self.id = id
        self.is_vault = is_vault
        self.parent_id = parent_id


class Link:
    """
    Represents a sharing link.
    scope ∈ {ANYONE, SPECIFIC}
    """
    def __init__(self, key: str, target_id: str, perms: Set[str], scope: str = "ANYONE"):
        self.key = key
        self.target_id = target_id
        self.perms = perms
        self.scope = scope
        self.recipients: Set[str] = set()


# ---------------------- GLOBAL STATE --------------------

SYSTEM_STATE = {
    "R": {},          # resources
    "L": {},          # links
    "U": {U_OWNER},   # users
}

# ---------------------- PERMISSION LOGIC ----------------

def req(action: str) -> str:
    """
    Maps ACTIONS → REQUIRED PERMISSION.
    Example: req("download") → view
             req("edit") → edit
    """
    if action in ACTIONS_THAT_MAP_TO_EDIT:
        return PERM_EDIT
    if action in ACTIONS_THAT_MAP_TO_VIEW:
        return PERM_VIEW
    raise ValueError(f"Unknown action: {action}")


def is_ancestor(p: str, c: str, state: Dict) -> bool:
    """True if p is an ancestor of c in the folder hierarchy."""
    node = state["R"].get(c)
    if not node:
        return False

    parent = node.parent_id
    while parent:
        if parent == p:
            return True
        parent = state["R"].get(parent).parent_id if parent in state["R"] else None

    return False


def ValidLink(link: Link, user: str, state: Dict, action: str = "view") -> bool:
    """
    Checks whether the link is usable by user for a given ACTION.
    ACTION is correctly interpreted through req().
    """

    # ----- 1. Identity / Possession Semantics -----
    if link.scope == "SPECIFIC" and user not in link.recipients:
        return False

    # ----- 2. Permission Semantics -----
    required_perm = req(action)

    # Direct permission
    if required_perm in link.perms:
        return True

    # Subsumption: edit → view
    if required_perm == PERM_VIEW and PERM_EDIT in link.perms:
        return True

    return False


def TotalPerms(user: str, resource_id: str, state: Dict, context: Dict = {}) -> Set[str]:
    """
    Computes all effective permissions over a resource.
    Includes identity checks, inheritance, and permission subsumption.
    """

    # Owner always gets full rights
    if user == U_OWNER:
        return {PERM_VIEW, PERM_EDIT}

    outcome = set()

    for link in state["L"].values():

        # Must pass identity + permission check for basic viewing
        if not ValidLink(link, user, state, action="view"):
            continue

        # Direct permission
        if link.target_id == resource_id:
            outcome.update(link.perms)

        # Inherited permission
        if is_ancestor(link.target_id, resource_id, state):
            outcome.update(link.perms)

    return outcome


# ---------------------- OPERATIONS -----------------------

class PolicyViolation(Exception):
    pass


def generate_key():
    return str(uuid.uuid4())


def CreateLink(u: str, target_id: str, scope: str, perms: Set[str], state: Dict, context: Dict = {}):
    """
    Create a new sharing link.
    """
    target = state["R"].get(target_id)
    if not target:
        raise PolicyViolation("Target resource does not exist.")

    # Vault resources cannot be shared
    if target.is_vault:
        raise PolicyViolation("Vault resources cannot be shared.")

    # Only owner or edit-holders can create
    if u != U_OWNER and PERM_EDIT not in TotalPerms(u, target_id, state):
        raise PolicyViolation("Insufficient permissions to create link.")

    key = generate_key()
    link = Link(key, target_id, perms, scope)
    state["L"][key] = link
    return link


def DeleteResource(u: str, resource_id: str, state: Dict, context: Dict = {}):
    """
    Delete a resource. Removes all links referencing it.
    """
    if u != U_OWNER and PERM_EDIT not in TotalPerms(u, resource_id, state):
        raise PolicyViolation("Insufficient permissions to delete the resource.")

    # Remove resource
    if resource_id in state["R"]:
        del state["R"][resource_id]

    # Remove links pointing to deleted resource
    state["L"] = {k: l for k, l in state["L"].items()
                  if l.target_id != resource_id}


def MoveResource(u: str, resource_id: str, new_parent_id: str, state: Dict, context: Dict = {}):
    """
    Move resource to another folder. Owner-only operation.
    """
    if u != U_OWNER:
        raise PolicyViolation("Only the owner can move resources.")

    resource = state["R"].get(resource_id)
    new_parent = state["R"].get(new_parent_id)

    if not resource or not new_parent:
        raise PolicyViolation("Resource or new parent not found.")

    # Prevent cycles
    if is_ancestor(resource_id, new_parent_id, state):
        raise PolicyViolation("Cannot move resource into its descendant.")

    resource.parent_id = new_parent_id
