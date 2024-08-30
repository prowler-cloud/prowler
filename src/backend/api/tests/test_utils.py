from api.utils import merge_dicts


class TestMergeDicts:
    def test_simple_merge(self):
        default_dict = {"key1": "value1", "key2": "value2"}
        replacement_dict = {"key2": "new_value2", "key3": "value3"}
        expected_result = {"key1": "value1", "key2": "new_value2", "key3": "value3"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_nested_merge(self):
        default_dict = {
            "key1": "value1",
            "key2": {"nested_key1": "nested_value1", "nested_key2": "nested_value2"},
        }
        replacement_dict = {
            "key2": {
                "nested_key2": "new_nested_value2",
                "nested_key3": "nested_value3",
            },
            "key3": "value3",
        }
        expected_result = {
            "key1": "value1",
            "key2": {
                "nested_key1": "nested_value1",
                "nested_key2": "new_nested_value2",
                "nested_key3": "nested_value3",
            },
            "key3": "value3",
        }

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_no_overlap(self):
        default_dict = {"key1": "value1"}
        replacement_dict = {"key2": "value2"}
        expected_result = {"key1": "value1", "key2": "value2"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_replacement_dict_empty(self):
        default_dict = {"key1": "value1", "key2": "value2"}
        replacement_dict = {}
        expected_result = {"key1": "value1", "key2": "value2"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_default_dict_empty(self):
        default_dict = {}
        replacement_dict = {"key1": "value1", "key2": "value2"}
        expected_result = {"key1": "value1", "key2": "value2"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_nested_empty_in_replacement_dict(self):
        default_dict = {"key1": {"nested_key1": "nested_value1"}}
        replacement_dict = {"key1": {}}
        expected_result = {"key1": {}}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_deep_nested_merge(self):
        default_dict = {"key1": {"nested_key1": {"deep_key1": "deep_value1"}}}
        replacement_dict = {"key1": {"nested_key1": {"deep_key1": "new_deep_value1"}}}
        expected_result = {"key1": {"nested_key1": {"deep_key1": "new_deep_value1"}}}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result
