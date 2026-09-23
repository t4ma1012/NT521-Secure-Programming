from test_data import *
from policy import POLICY


def json_search(key, input_object, role=None):
    # Role-based access control
    if role is not None:
        allowed_roles = POLICY.get(key)

        # Key có policy nhưng role không được phép
        if allowed_roles is not None and role not in allowed_roles:
            return []

    ret_val = []

    if isinstance(input_object, dict):
        for k, v in input_object.items():
            if k == key:
                temp = {k: v}
                ret_val.append(temp)

            if isinstance(v, dict):
                ret_val.extend(json_search(key, v, role))

            elif isinstance(v, list):
                for item in v:
                    if not isinstance(item, (str, int)):
                        ret_val.extend(json_search(key, item, role))

    else:
        for val in input_object:
            if not isinstance(val, (str, int)):
                ret_val.extend(json_search(key, val, role))

    return ret_val


print(json_search("issueSummary", data))
