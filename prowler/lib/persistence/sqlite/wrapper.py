import builtins

from datetime import datetime

from .constants import IMMUTABLE_HASHABLE_TYPES

SKIP_METHODS = (
    # Special methods
    '__getitem__', '__repr__', '__str__', '__bytes__', '__bool__', '__len__', '__iter__', '__reversed__',
    '__contains__', '__add__', '__sub__', '__mul__', '__floordiv__', '__mod__', '__divmod__', '__pow__',
    '__lshift__', '__rshift__', '__and__', '__xor__', '__or__', '__radd__', '__rsub__', '__getstate__',
    '__class__', '__delattr__', '__dir__', '__doc__', '__format__', '__ge__', '__gt__', '__hash__',
    '__init__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__setstate__',
    '__sizeof__', '__subclasshook__', '__weakref__', '__call__', '__del__', '__init_subclass__', '__instancecheck__',

    # Special methods: setters
    '__setattr__', '__setitem__',


    # Custom methods
    'obj', 'callback', 'parent', 'key'
)


def wrap_fn(original_fn, callback, parent_reference):

    def wrapped_fn(*args, **kwargs):
        result = original_fn(*args, **kwargs)
        callback(parent_reference)
        return result

    return wrapped_fn


class Wrapper:

    def __init__(self, parent_reference, real_obj, callback: callable = None):
        self.obj = real_obj
        self.callback = callback
        self.parent = parent_reference

    # region generic_magic_methods
    def __eq__(self, other):
        return object.__getattribute__(self, 'obj') == other

    def __repr__(self):
        return repr(object.__getattribute__(self, 'obj'))

    def __str__(self):
        return str(object.__getattribute__(self, 'obj'))

    def __bytes__(self):
        return bytes(object.__getattribute__(self, 'obj'))

    def __bool__(self):
        return bool(object.__getattribute__(self, 'obj'))

    def __len__(self):
        return len(object.__getattribute__(self, 'obj'))

    def __iter__(self):
        return iter(object.__getattribute__(self, 'obj'))

    def __reversed__(self):
        return reversed(object.__getattribute__(self, 'obj'))

    def __contains__(self, key):
        return key in object.__getattribute__(self, 'obj')

    def __add__(self, other):
        return object.__getattribute__(self, 'obj') + other

    def __sub__(self, other):
        return object.__getattribute__(self, 'obj') - other

    def __mul__(self, other):
        return object.__getattribute__(self, 'obj') * other

    def __floordiv__(self, other):
        return object.__getattribute__(self, 'obj') // other

    def __mod__(self, other):
        return object.__getattribute__(self, 'obj') % other

    def __divmod__(self, other):
        return divmod(object.__getattribute__(self, 'obj'), other)

    def __pow__(self, other):
        return object.__getattribute__(self, 'obj') ** other

    def __lshift__(self, other):
        return object.__getattribute__(self, 'obj') << other

    def __rshift__(self, other):
        return object.__getattribute__(self, 'obj') >> other

    def __and__(self, other):
        return object.__getattribute__(self, 'obj') & other

    def __xor__(self, other):
        return object.__getattribute__(self, 'obj') ^ other

    def __or__(self, other):
        return object.__getattribute__(self, 'obj') | other

    def __radd__(self, other):
        return other + object.__getattribute__(self, 'obj')

    def __rsub__(self, other):
        return other - object.__getattribute__(self, 'obj')

    def __getstate__(self):
        """
        Method required for pickling the object.
        Returns the state of the object for serialization.
        """

        try:
            ref = builtins.prowler_memory_referencies
        except AttributeError:
            builtins.prowler_memory_referencies = {}
            ref = builtins.prowler_memory_referencies

        callback_fn = object.__getattribute__(self, 'callback')
        callback_id = id(callback_fn)

        # Keep a reference to the callback function

        ref[callback_id] = callback_fn

        return {
            'obj': object.__getattribute__(self, 'obj'),
            'parent': object.__getattribute__(self, 'parent'),
            'callback_reference': callback_id
        }

    def __setstate__(self, state):
        """
        Method required for unpickling the object.
        Takes the state of the object for deserialization.
        """
        __dict__ = object.__getattribute__(self, '__dict__')
        __dict__.update(state)

        # Restore the callback function
        callback_ref = builtins.prowler_memory_referencies[state['callback_reference']]
        __dict__['callback'] = callback_ref

    # endregion

    def __getitem__(self, key_or_index):
        """For list and dict. When we get an item in a list or dict"""
        return object.__getattribute__(self, 'obj')[key_or_index]

    def __getattr__(self, item):
        return object.__getattribute__(self, item)

    def __getattribute__(self, item):
        # If the attribute is a special method, we need to return the method itself
        if item in SKIP_METHODS:
            if isinstance(item, Wrapper):
                return item

            else:
                return object.__getattribute__(self, item)

        # If it's a property, we need to wrap it in a proxy object if there is not already wrapped
        target_attr = getattr(self.obj, item)
        target_attr_name = str(type(target_attr))
        callback = object.__getattribute__(self, 'callback')
        parent_reference = object.__getattribute__(self, 'parent')

        if target_attr is None:
            ret = None

        elif "function" in target_attr_name or "method" in target_attr_name:
            ret = wrap_fn(target_attr, callback, parent_reference)

        elif type(target_attr) in IMMUTABLE_HASHABLE_TYPES:
            ret = target_attr

        elif type(target_attr) is Wrapper:
            ret = target_attr

        else:
            ret = Wrapper(parent_reference=parent_reference, real_obj=target_attr, callback=callback)

        return ret

    def __setattr__(self, key, value):
        """For object. When we set an attribute"""

        if key in SKIP_METHODS:
            return object.__setattr__(self, key, value)

        real_obj = object.__getattribute__(self, 'obj')
        callback = object.__getattribute__(self, 'callback')
        parent_reference = object.__getattribute__(self, 'parent')

        try:
            # Check if value is a simple type or a complex type: list, dict or object
            if type(value) in (str, int, float, bool, tuple, frozenset, bytes, datetime):
                object.__setattr__(real_obj, key, value)

            else:
                object.__setattr__(real_obj, key, Wrapper(parent_reference=parent_reference, real_obj=value, callback=callback))

        finally:

            if callback:
                callback(parent_reference)

    def __setitem__(self, key, value):
        """For list and dict. When we set an item in a list or dict"""

        list_or_dict = object.__getattribute__(self, 'obj')
        callback = object.__getattribute__(self, 'callback')
        parent_reference = object.__getattribute__(self, 'parent')

        # Check if value is a simple type or a complex type: list, dict or object
        if type(value) in (str, int, float, bool, tuple, frozenset, bytes, datetime):
            list_or_dict[key] = value

        # If value is a complex type, we need to wrap it in a proxy object
        else:
            list_or_dict[key] = Wrapper(
                parent_reference=parent_reference, real_obj=value, callback=object.__getattribute__(self, 'callback')
            )

        if callback:
            callback(parent_reference)
