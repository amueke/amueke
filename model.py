
# model.py
"""
Full OneDrive (Personal) policy model implementation.

Adds:
 - holding relation (possession of link tokens)
 - link constraints (expiry, password)
 - context Γ with tnow, auth_level, provided_pw
 - VaultAccess (MFA barrier)
 - DeleteLink, RemoveUser, UpdateConstraints, ChangePermissions
 - decide_access authorization oracle
 - GiveLinkToUser / RevokeLinkFromUser helpers
"""

import uuid
from typing import Dict, Set, Any, Optional

# --- Entity Definitions and Constants ---

U_OWNER = "u_owner"
PERM_VIEW = "view"
PERM_EDIT = "edit"

# Auth levels
AUTH_NONE = "none"
AUTH_STANDARD = "standard"
AUTH_MFA = "mfa"

# Link scopes
SCOPE_ANYONE = "ANYONE"
SCOPE_SPECIFIC = "SPECIFIC"

# Actions allowed in the system
ACTIONS = {"view", "download", "edit", "delete", "share"}


class Resource:
    """Represents files and folders (Rfiles and Rfolders)."""

    def __init__(self, id: str, is_vault: bool = False, parent_id: Optional[str] = None):
        self.id = id
        self.is_vault = is_vault
        self.parent_id = parent_id


class Link:
    """
    Represents a sharing token l ∈ L.
    - key: unique token string (capability)
    - target_id: resource id it points to
    - perms: set of permissions (subset of {view, edit})
    - scope: ANYONE or SPECIFIC
    - recipients: set of allowed users if SPECIFIC
    - constraints: dict possibly containing 'expiry' and 'password'
    """

    def __init__(
        self,
        key: str,
        target_id: str,
        perms: Set[str],
        scope: str = SCOPE_ANYONE,
        constraints: Optional[Dict[str, Any]] = None,
    ):
        self.key = key
        self.target_id = target_id
        self.perms = set(perms)
        self.scope = scope
        self.recipients: Set[str] = set()
        self.constraints: Dict[str, Any] = constraints.copy() if constraints else {}


# --- Global System State (Γ) ---

SYSTEM_STATE: Dict[str, Any] = {
    "R": {},  # resources
    "L": {},  # links
    "U": {U_OWNER},  # users
    "holding": {},  # holding relation: {link_key: set(user_ids)}
}


# --- Utility Functions ---

def req(action: str) -> str:
    if action in ["edit", "delete", "share"]:
        return PERM_EDIT
    if action in ["view", "download"]:
        return PERM_VIEW
    raise ValueError(f"Unknown action: {action}")


def is_ancestor(ancestor_id: str, resource_id: str, state: Dict) -> bool:
    resource = state["R"].get(resource_id)
    if not resource:
        return False
    parent = resource.parent_id
    while parent:
        if parent == ancestor_id:
            return True
        parent_res = state["R"].get(parent)
        if not parent_res:
            break
        parent = parent_res.parent_id
    return False


def generate_key() -> str:
    return str(uuid.uuid4())


def _normalize_context(context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if context is None:
        context = {}
    return {
        "tnow": context.get("tnow", 0),
        "auth_level": context.get("auth_level", AUTH_NONE),
        "provided_pw": context.get("provided_pw", None),
    }


# --- Holding relation helpers ---

def GiveLinkToUser(user: str, link_key: str, state: Dict) -> None:
    if link_key not in state["L"]:
        raise ValueError("Link does not exist.")
    holders = state["holding"].setdefault(link_key, set())
    holders.add(user)


def RevokeLinkFromUser(user: str, link_key: str, state: Dict) -> None:
    holders = state["holding"].get(link_key)
    if not holders:
        return
    holders.discard(user)
    if not holders:
        state["holding"].pop(link_key, None)


# --- Vault Access Predicate ---

def VaultAccess(user: str, resource_id: str, state: Dict, context: Optional[Dict[str, Any]] = None) -> bool:
    ctx = _normalize_context(context)
    resource = state["R"].get(resource_id)
    if not resource:
        return False
    if not resource.is_vault:
        return True
    return (user == U_OWNER) and (ctx["auth_level"] == AUTH_MFA)


# --- ValidLink and TotalPerms ---

def ValidLink(link: Link, user: str, action: str = "view", state: Dict = SYSTEM_STATE, context: Optional[Dict[str, Any]] = None) -> bool:
    """
    ValidLink(l, u, a, Γ):
      1. Possession: (u, l) in holding required for ANYONE and SPECIFIC links
      2. Identity: SPECIFIC requires u ∈ recipients; ANYONE allowed
      3. Expiration
      4. Password
      5. Permissions
    """
    ctx = _normalize_context(context)

    # 1. Possession: always required
    holders = state.get("holding", {}).get(link.key, set())
    if user not in holders:
        return False

    # 2. Identity
    if link.scope == SCOPE_SPECIFIC and user not in link.recipients:
        return False

    # 3. Expiration
    expiry = link.constraints.get("expiry")
    if expiry is not None and ctx["tnow"] >= expiry:
        return False

    # 4. Password
    if "password" in link.constraints:
        provided = ctx["provided_pw"]
        if provided != link.constraints.get("password"):
            return False

    # 5. Permissions
    needed = req(action)
    if needed in link.perms:
        return True
    if needed == PERM_VIEW and PERM_EDIT in link.perms:
        return True
    return False


def TotalPerms(user: str, resource_id: str, state: Dict, context: Optional[Dict[str, Any]] = None) -> Set[str]:
    ctx = _normalize_context(context)
    effective: Set[str] = set()

    if user == U_OWNER:
        return {PERM_VIEW, PERM_EDIT}

    for link in state["L"].values():
        if not ValidLink(link, user, action="view", state=state, context=ctx):
            continue
        if link.target_id == resource_id:
            effective.update(link.perms)
        if is_ancestor(link.target_id, resource_id, state):
            effective.update(link.perms)

    if PERM_EDIT in effective:
        effective.add(PERM_VIEW)
    return effective


# --- Operations ---

class PolicyViolation(Exception):
    pass


def CreateLink(u: str, target_id: str, scope: str, perms: Set[str], state: Dict,
               context: Optional[Dict[str, Any]] = None, constraints: Optional[Dict[str, Any]] = None) -> Link:
    ctx = _normalize_context(context or {})
    target = state["R"].get(target_id)
    if not target:
        raise PolicyViolation("Target resource does not exist.")
    if target.is_vault:
        raise PolicyViolation("Vault resources cannot be shared via links.")
    has_edit = PERM_EDIT in TotalPerms(u, target_id, state, context=ctx)
    if u != U_OWNER and not has_edit:
        raise PolicyViolation("Only owner or users with edit permission can create links.")
    if constraints and scope != SCOPE_ANYONE:
        raise PolicyViolation("Constraints only apply to ANYONE links.")
    key = generate_key()
    link = Link(key=key, target_id=target_id, perms=set(perms), scope=scope, constraints=constraints)
    state["L"][key] = link
    GiveLinkToUser(u, key, state)
    return link


def DeleteResource(u: str, resource_id: str, state: Dict, context: Optional[Dict[str, Any]] = None) -> None:
    ctx = _normalize_context(context)
    if u != U_OWNER and PERM_EDIT not in TotalPerms(u, resource_id, state, context=ctx):
        raise PolicyViolation("Deletion requires edit permission.")
    state["R"].pop(resource_id, None)
    keys_to_remove = [k for k, l in list(state["L"].items()) if l.target_id == resource_id]
    for k in keys_to_remove:
        DeleteLink(u=U_OWNER, link_key=k, state=state)


def MoveResource(u: str, resource_id: str, new_parent_id: str, state: Dict, context: Optional[Dict[str, Any]] = None) -> None:
    if u != U_OWNER:
        raise PolicyViolation("Only the owner can move resources.")
    res = state["R"].get(resource_id)
    new_parent = state["R"].get(new_parent_id)
    if not res or not new_parent:
        raise PolicyViolation("Resource or parent




  



    






  

    





   

  



  
    
  


  
