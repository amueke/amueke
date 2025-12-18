# model.py
"""
Full OneDrive (Personal) policy model implementation.
Formal-spec compliant version.
"""

import uuid
from typing import Dict, Set, Any, Optional

# --- Entity Definitions and Constants ---

U_OWNER = "u_owner"
PERM_VIEW = "view"
PERM_EDIT = "edit"

AUTH_NONE = "none"
AUTH_MFA = "mfa"

SCOPE_ANYONE = "ANYONE"
SCOPE_SPECIFIC = "SPECIFIC"


class Resource:
    def __init__(self, id: str, is_vault: bool = False, parent_id: Optional[str] = None):
        self.id = id
        self.is_vault = is_vault
        self.parent_id = parent_id


class Link:
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


# --- Global System State Γ ---

SYSTEM_STATE: Dict[str, Any] = {
    "R": {},
    "L": {},
    "U": {U_OWNER},
    "holding": {},
}


# --- Utility Functions ---

def req(action: str) -> str:
    if action in {"edit", "delete", "share"}:
        return PERM_EDIT
    if action in {"view", "download"}:
        return PERM_VIEW
    raise ValueError(action)


def is_ancestor(ancestor_id: str, resource_id: str, state: Dict) -> bool:
    res = state["R"].get(resource_id)
    while res and res.parent_id:
        if res.parent_id == ancestor_id:
            return True
        res = state["R"].get(res.parent_id)
    return False


def generate_key() -> str:
    return str(uuid.uuid4())


def _normalize_context(ctx: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    ctx = ctx or {}
    return {
        "tnow": ctx.get("tnow", 0),
        "auth_level": ctx.get("auth_level", AUTH_NONE),
        "provided_pw": ctx.get("provided_pw"),
    }


# --- Holding Relation ---

def GiveLinkToUser(user: str, link_key: str, state: Dict) -> None:
    state["holding"].setdefault(link_key, set()).add(user)


def RevokeLinkFromUser(user: str, link_key: str, state: Dict) -> None:
    holders = state["holding"].get(link_key)
    if holders:
        holders.discard(user)
        if not holders:
            state["holding"].pop(link_key, None)


# --- Authorization Logic ---

def ValidLink(
    link: Link,
    user: str,
    action: str,
    state: Dict,
    context: Optional[Dict[str, Any]] = None,
) -> bool:
    ctx = _normalize_context(context)

    # Possession required ONLY for SPECIFIC links
    if link.scope == SCOPE_SPECIFIC:
        if user not in state["holding"].get(link.key, set()):
            return False
        if user not in link.recipients:
            return False

    # Expiry
    expiry = link.constraints.get("expiry")
    if expiry is not None and ctx["tnow"] >= expiry:
        return False

    # Password
    if "password" in link.constraints:
        if ctx["provided_pw"] != link.constraints["password"]:
            return False

    needed = req(action)
    return needed in link.perms or (
        needed == PERM_VIEW and PERM_EDIT in link.perms
    )


def TotalPerms(
    user: str,
    resource_id: str,
    state: Dict,
    context: Optional[Dict[str, Any]] = None,
) -> Set[str]:
    if user == U_OWNER:
        return {PERM_VIEW, PERM_EDIT}

    perms: Set[str] = set()
    for link in state["L"].values():
        if not ValidLink(link, user, "view", state, context):
            continue
        if link.target_id == resource_id or is_ancestor(link.target_id, resource_id, state):
            perms |= link.perms

    if PERM_EDIT in perms:
        perms.add(PERM_VIEW)
    return perms


# --- Operations ---

class PolicyViolation(Exception):
    pass


def CreateLink(
    u: str,
    target_id: str,
    scope: str,
    perms: Set[str],
    state: Dict,
    context: Optional[Dict[str, Any]] = None,
    constraints: Optional[Dict[str, Any]] = None,
) -> Link:
    target = state["R"].get(target_id)
    if not target:
        raise PolicyViolation("Target resource does not exist.")
    if target.is_vault:
        raise PolicyViolation("Vault resources cannot be shared via links.")

    if u != U_OWNER and PERM_EDIT not in TotalPerms(u, target_id, state, context):
        raise PolicyViolation("Only owner or editors may create links.")

    key = generate_key()
    link = Link(key, target_id, perms, scope, constraints)
    state["L"][key] = link
    GiveLinkToUser(u, key, state)
    return link


def DeleteLink(u: str, link_key: str, state: Dict) -> None:
    state["L"].pop(link_key, None)
    state["holding"].pop(link_key, None)


def DeleteResource(
    u: str,
    resource_id: str,
    state: Dict,
    context: Optional[Dict[str, Any]] = None,
) -> None:
    if u != U_OWNER and PERM_EDIT not in TotalPerms(u, resource_id, state, context):
        raise PolicyViolation("Deletion requires edit permission.")

    # Recursive subtree deletion
    to_delete = {resource_id}
    changed = True
    while changed:
        changed = False
        for rid, res in list(state["R"].items()):
            if res.parent_id in to_delete and rid not in to_delete:
                to_delete.add(rid)
                changed = True

    for rid in to_delete:
        state["R"].pop(rid, None)

    for k, l in list(state["L"].items()):
        if l.target_id in to_delete:
            DeleteLink(U_OWNER, k, state)


def MoveResource(
    u: str,
    resource_id: str,
    new_parent_id: str,
    state: Dict,
    context: Optional[Dict[str, Any]] = None,
) -> None:
    if u != U_OWNER:
        raise PolicyViolation("Only the owner can move resources.")

    res = state["R"].get(resource_id)
    parent = state["R"].get(new_parent_id)
    if not res or not parent:
        raise PolicyViolation("Resource or parent does not exist.")

    # EFFECT: change inheritance source
    res.parent_id = new_parent_id









   



    






  

    





   

  



  
    
  


  
