import copy
import logging
from types import MappingProxyType

from policy import POLICY

logger = logging.getLogger(__name__)

VALID_ROLES = frozenset({"admin", "operator", "viewer"})
SENSITIVE_KEYS = frozenset({"apiKey", "managementIpAddress"})

# SR-04: immutable snapshot of POLICY, so runtime edits to policy.POLICY
# (e.g. POLICY["apiKey"].append("viewer")) cannot widen access.
_POLICY = MappingProxyType({k: frozenset(v) for k, v in POLICY.items()})


def _is_authorized(key, role):
    # SR-03: exact str type (no subclasses / custom __eq__), exact match.
    if type(role) is not str or role not in VALID_ROLES:
        return False
    # SR-02: keys not listed in POLICY are denied for every role.
    if type(key) is not str or key not in _POLICY:
        return False
    # SR-01
    return role in _POLICY[key]


def json_search(key, input_object, role=None):
    """Return every value stored under `key` anywhere in `input_object`,
    only if `role` is allowed to read `key` according to POLICY."""
    allowed = _is_authorized(key, role)

    # SR-07: audit sensitive fields without logging their values.
    if key in SENSITIVE_KEYS:
        if allowed:
            logger.info("json_search key=%s role=%r allowed", key, role)
        else:
            logger.warning("json_search key=%s role=%r denied", key, role)

    # SR-01 / SR-06: deny before traversing, silently.
    if not allowed:
        return []

    # SR-05: iterative pre-order traversal (no recursion depth limit).
    # Children are pushed in reverse so results keep document order.
    results = []
    stack = [input_object]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            children = []
            for k, v in node.items():
                if k == key:
                    # SR-04: return copies, never references into input data.
                    results.append(copy.deepcopy(v))
                if isinstance(v, (dict, list)):
                    children.append(v)
            stack.extend(reversed(children))
        elif isinstance(node, list):
            stack.extend(reversed([v for v in node if isinstance(v, (dict, list))]))
    return results
