
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
    - recipients: set of allowed users if SPECIFIC (subset of authenticated users)
    - constraints: dict possibly containing 'expiry' (numeric timestamp) and 'password' (string)
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
        # constraints: e.g. {"expiry": 1670000000, "password": "s3cr3t"}
        self.constraints: Dict[str, Any] = constraints.copy() if constraints else {}


# --- Global System State (Γ) ---

SYSTEM_STATE: Dict[str, Any] = {
    "R": {},  # resources {resource_id: Resource}
    "L": {},  # links   {key: Link}
    "U": {U_OWNER},  # users set
    # holding relation: map link_key -> set of users who possess the link token
    "holding": {},  # {link_key: set(user_ids)}
}


# --- Utility Functions (Relations and Predicates) ---


def req(action: str) -> str:
    """Map action to required permission in P = {view, edit}."""
    if action in ["edit", "delete", "share"]:
        return PERM_EDIT
    if action in ["view", "download"]:
        return PERM_VIEW
    raise ValueError(f"Unknown action: {action}")


def is_ancestor(ancestor_id: str, resource_id: str, state: Dict) -> bool:
    """True if ancestor_id is a (proper) ancestor of resource_id."""
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
    """Generate a unique key; uniqueness asserted by using UUID."""
    return str(uuid.uuid4())


# --- Context Γ Type ---
# context is a dict with keys:
#  - "tnow": numeric timestamp (int or float)
#  - "auth_level": one of {none, standard, mfa}
#  - "provided_pw": optional password string provided by requester
# If omitted, defaults are used when appropriate.


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
    """
    Give possession of the link token to a user: (user, link) ∈ holding
    """
    if link_key not in state["L"]:
        raise ValueError("Link does not exist.")
    holders = state["holding"].setdefault(link_key, set())
    holders.add(user)


def RevokeLinkFromUser(user: str, link_key: str, state: Dict) -> None:
    """
    Revoke possession of the link token from a user.
    """
    holders = state["holding"].get(link_key)
    if not holders:
        return
    holders.discard(user)
    if not holders:
        # keep empty set or remove; remove to keep invariant clean
        state["holding"].pop(link_key, None)


# --- Vault Access Predicate ---


def VaultAccess(user: str, resource_id: str, state: Dict, context: Optional[Dict[str, Any]] = None) -> bool:
    """
    Implements VaultAccess(u, r, Γ):

    - If r not in R_vault => True
    - If r in R_vault and u == uowner and auth_level == mfa => True
    - Else False
    """
    ctx = _normalize_context(context)
    resource = state["R"].get(resource_id)
    if not resource:
        # If resource doesn't exist, treat as denied at this layer
        return False
    if not resource.is_vault:
        return True
    # resource is in vault
    return (user == U_OWNER) and (ctx["auth_level"] == AUTH_MFA)


# --- ValidLink and TotalPerms (Context-aware) ---


def ValidLink(link: Link, user: str, action: str = "view", state: Dict = SYSTEM_STATE, context: Optional[Dict[str, Any]] = None) -> bool:
    """
    ValidLink(l, u, a, Γ) per Section 7.2:

    Checks:
      1. Possession: (u, l) in holding
      2. Identity: (l.scope == ANYONE) OR (u in l.recipients)
      3. Expiration: if 'expiry' in l.constraints then tnow < expiry
      4. Password: if 'password' in l.constraints then provided_pw == l.constraints['password']
      5. Permissions: req(a) ∈ l.permseffective (with subsumption)
    """
    ctx = _normalize_context(context)

    # 1. Possession: user must possess the link token
    holders = state.get("holding", {}).get(link.key, set())
    if user not in holders:
        return False

    # 2. Identity: SPECIFIC must have user in recipients; ANYONE allowed
    if link.scope == SCOPE_SPECIFIC and user not in link.recipients:
        return False

    # 3. Expiration
    expiry = link.constraints.get("expiry")
    if expiry is not None:
        if ctx["tnow"] >= expiry:
            return False

    # 4. Password protection
    if "password" in link.constraints:
        provided = ctx["provided_pw"]
        if provided != link.constraints.get("password"):
            return False

    # 5. Permissions: check required permission for the action
    needed = req(action)

    # direct permission
    if needed in link.perms:
        return True

    # subsumption: edit -> view
    if needed == PERM_VIEW and PERM_EDIT in link.perms:
        return True

    return False


def TotalPerms(user: str, resource_id: str, state: Dict, context: Optional[Dict[str, Any]] = None) -> Set[str]:
    """
    TotalPerms(u, r, Γ) = DirectPerms ∪ InheritedPerms
    Uses ValidLink with action='view' to check identity/possession/constraints as the spec requires.

    Returns effective permissions with subsumption applied (edit -> view).
    """
    ctx = _normalize_context(context)
    effective: Set[str] = set()

    # Owner has full rights implicitly
    if user == U_OWNER:
        return {PERM_VIEW, PERM_EDIT}

    for link in state["L"].values():
        # A link can contribute only if it's considered valid for 'view' check
        if not ValidLink(link, user, action="view", state=state, context=ctx):
            continue

        # direct target
        if link.target_id == resource_id:
            effective.update(link.perms)

        # inherited from ancestor
        if is_ancestor(link.target_id, resource_id, state):
            effective.update(link.perms)

    # subsumption
    if PERM_EDIT in effective:
        effective.add(PERM_VIEW)

    return effective


# --- Operational Semantics (State Transitions & Admin Ops) ---


class PolicyViolation(Exception):
    """For policy precondition failures."""
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
    """
    CreateLink(u, target, scope, perms, constraints)

    Precondition: (u == uowner OR edit in TotalPerms(u, target, Γ)) AND target not in R_vault
    Note: constraints allowed only for ANYONE links (spec constraint)
    """
    ctx = _normalize_context(context or {})
    target = state["R"].get(target_id)
    if not target:
        raise PolicyViolation("Target resource does not exist.")

    # Vault non-shareability
    if target.is_vault:
        raise PolicyViolation("Vault resources cannot be shared via links.")

    has_edit = PERM_EDIT in TotalPerms(u, target_id, state, context=ctx)

    if u != U_OWNER and not has_edit:
        raise PolicyViolation("Only owner or users with edit permission can create links.")

    # Constraint-Scope Consistency: only ANYONE links may have constraints per spec
    if constraints and scope != SCOPE_ANYONE:
        raise PolicyViolation("Constraints (expiry/password) only apply to ANYONE links.")

    # create link
    key = generate_key()
    link = Link(key=key, target_id=target_id, perms=set(perms), scope=scope, constraints=constraints)
    state["L"][key] = link

    # By default, give possession to the creator (owner creates links and "owns" the link token)
    GiveLinkToUser(u, key, state)

    return link


def DeleteResource(u: str, resource_id: str, state: Dict, context: Optional[Dict[str, Any]] = None) -> None:
    """
    DeleteResource(u, resource):
    Precondition: u == u_owner OR edit ∈ TotalPerms(u, resource, Γ)
    Effect: remove resource and garbage collect links pointing to it
    """
    ctx = _normalize_context(context)
    if u != U_OWNER and PERM_EDIT not in TotalPerms(u, resource_id, state, context=ctx):
        # message expected by tests
        raise PolicyViolation("Deletion requires edit permission.")

    # remove resource (if exists)
    state["R"].pop(resource_id, None)

    # remove links targeting this resource
    keys_to_remove = [k for k, l in list(state["L"].items()) if l.target_id == resource_id]
    for k in keys_to_remove:
        DeleteLink(u=U_OWNER, link_key=k, state=state)  # owner can delete link; use owner to remove entirely


def MoveResource(u: str, resource_id: str, new_parent_id: str, state: Dict, context: Optional[Dict[str, Any]] = None) -> None:
    """
    MoveResource(owner only). Prevent cycles.
    """
    if u != U_OWNER:
        raise PolicyViolation("Only the owner can move resources.")

    res = state["R"].get(resource_id)
    new_parent = state["R"].get(new_parent_id)
    if not res or not new_parent:
        raise PolicyViolation("Resource or parent not found.")

    # Prevent cycles
    if is_ancestor(resource_id, new_parent_id, state):
        raise PolicyViolation("Cannot move a resource into its own descendant.")

    res.parent_id = new_parent_id


# --- Link & Recipient Management ---


def DeleteLink(u: str, link_key: str, state: Dict) -> None:
    """
    DeleteLink(owner only). Removes the link entirely and clears all holdings.
    """
    if u != U_OWNER:
        raise PolicyViolation("Only owner can delete a link (global revocation).")
    link = state["L"].pop(link_key, None)
    # remove holding entries
    state["holding"].pop(link_key, None)


def RemoveUser(u: str, link_key: str, target_user: str, state: Dict) -> None:
    """
    RemoveUser(owner, link_key, target_user):
    Mutates recipients(l) = recipients(l) \ {target_user}
    Precondition: link.scope == SPECIFIC
    """
    if u != U_OWNER:
        raise PolicyViolation("Only owner may remove users from a specific link.")
    link = state["L"].get(link_key)
    if not link:
        raise PolicyViolation("Link not found.")
    if link.scope != SCOPE_SPECIFIC:
        raise PolicyViolation("RemoveUser only supports SPECIFIC links.")
    link.recipients.discard(target_user)


def UpdateConstraints(u: str, link_key: str, new_constraints: Dict[str, Any], state: Dict) -> None:
    """
    UpdateConstraints(owner, link_key, new_constraints): set constraints for link.
    Only owner may update constraints. Constraints only allowed on ANYONE links per spec.
    """
    if u != U_OWNER:
        raise PolicyViolation("Only owner may update link constraints.")
    link = state["L"].get(link_key)
    if not link:
        raise PolicyViolation("Link not found.")
    if link.scope != SCOPE_ANYONE and new_constraints:
        raise PolicyViolation("Constraints may only be set on ANYONE links.")
    link.constraints = new_constraints.copy() if new_constraints else {}


def ChangePermissions(u: str, link_key: str, new_perms: Set[str], state: Dict) -> None:
    """
    ChangePermissions(owner, link_key, new_perms)
    Owner-only operation. Enforce that new_perms is either {view} or {view, edit}
    """
    if u != U_OWNER:
        raise PolicyViolation("Only owner may change link permissions.")
    if new_perms not in ({PERM_VIEW}, {PERM_VIEW, PERM_EDIT}):
        raise PolicyViolation("Invalid permission set.")
    link = state["L"].get(link_key)
    if not link:
        raise PolicyViolation("Link not found.")
    link.perms = set(new_perms)


# --- Authorization Oracle ---


def decide_access(user: str, resource_id: str, action: str, state: Dict, context: Optional[Dict[str, Any]] = None) -> str:
    """
    decide_access(u, r, a, Γ) -> "GRANT" or "DENY"

    Algorithm per spec:
      - DENY if not VaultAccess
      - GRANT if user == owner
      - GRANT if req(a) in TotalPerms(user, resource, Γ)
      - DENY otherwise
    """
    if action not in ACTIONS:
        raise ValueError("Unknown action requested.")

    ctx = _normalize_context(context)

    # Vault barrier
    if not VaultAccess(user, resource_id, state, context=ctx):
        return "DENY"

    # owner shortcut
    if user == U_OWNER:
        return "GRANT"

    effective = TotalPerms(user, resource_id, state, context=ctx)
    if req(action) in effective:
        return "GRANT"
    return "DENY"
