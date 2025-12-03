# model.py - Conceptual Structure

class Resource:
    """Represents R_files, R_folders, R_vault, and the hierarchy."""
    def __init__(self, id, is_vault=False, parent_id=None, owner="u_owner"):
        self.id = id
        self.is_vault = is_vault
        self.parent_id = parent_id
        self.owner = owner

class Link:
    """Represents a capability token l in L."""
    def __init__(self, key, target_id, perms, scope="ANYONE", constraints=None):
        self.key = key
        self.target_id = target_id
        self.perms = perms # e.g., {"view"}, {"view", "edit"}
        self.scope = scope
        self.constraints = constraints or {}

# Global System State (Gamma - Γ)
SYSTEM_STATE = {
    "R": {},    # Dictionary of Resource objects
    "L": {},    # Dictionary of Link objects
    "U": {"u_owner"},
}

def is_ancestor(ancestor_id, resource_id):
    """(Helper for Hierarchical Inheritance) Implements is_ancestor(p, c)."""
    # Logic to recursively check parent IDs
    pass

def TotalPerms(user, resource_id, state):
    """Implements TotalPerms(u, r, Γ) from Section 7.4. [cite: 179]"""
    # Logic to compute the union of direct and inherited permissions
    pass

# Operational Semantics (State Transitions)
def CreateLink(u, target_id, scope, perms, state):
    """Implements CreateLink from Section 9.1."""
    # 1. Check Precondition: (u=u_owner V edit in TotalPerms) and target not in R_vault 
    # 2. Effect: Create new Link object, add to state["L"] [cite: 201]
    pass

# ... Other operations like MoveResource, DeleteResource
