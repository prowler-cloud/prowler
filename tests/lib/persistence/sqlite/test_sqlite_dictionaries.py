from prowler.lib.persistence.sqlite import SQLiteDict


class Test_SqliteDict:
    def test_create_dictionary(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        assert dictionary["test"] == "test"

    def test_create_dictionary_add_two_elements(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert dictionary["test"] == "test"
        assert dictionary["test2"] == "test2"

    def test_create_dictionary_add_two_elements_with_same_key(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test"] = "test2"
        assert dictionary["test"] == "test2"

    def test_create_dictionary_add_two_elements_with_same_key_and_value(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test"] = "test"
        assert dictionary["test"] == "test"

    def test_delete_value(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        del dictionary["test"]
        assert "test" not in dictionary

    def test_dictionary_length(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert len(dictionary) == 2

    def test_dictionary_clear(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        dictionary.clear()
        assert len(dictionary) == 0

    def test_dictionary_contains(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert "test" in dictionary
        assert "test2" in dictionary
        assert "test3" not in dictionary

    def test_dictionary_getitem(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert dictionary["test"] == "test"
        assert dictionary["test2"] == "test2"

    def test_dictionary_setitem(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        dictionary["test3"] = "test3"
        assert dictionary["test"] == "test"
        assert dictionary["test2"] == "test2"
        assert dictionary["test3"] == "test3"

    def test_dictionary_iter(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        for key, value in dictionary.items():
            assert key in ["test", "test2"]
            assert value in ["test", "test2"]

    def test_dictionary_keys(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert "test" in dictionary.keys()
        assert "test2" in dictionary.keys()
        assert "test3" not in dictionary.keys()

    def test_dictionary_values(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert "test" in dictionary.values()
        assert "test2" in dictionary.values()
        assert "test3" not in dictionary.values()

    def test_dictionary_items(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        for key, value in dictionary.items():
            assert key in ["test", "test2"]

    def test_dictionary_pop(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert dictionary.pop("test") == "test"
        assert "test" not in dictionary
        assert "test2" in dictionary

    def test_dictionary_popitem(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert dictionary.popitem() == ("test", "test")
        assert "test" not in dictionary
        assert "test2" in dictionary

    def test_dictionary_update(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        dictionary.update({"test3": "test3"})
        assert dictionary["test"] == "test"
        assert dictionary["test2"] == "test2"
        assert dictionary["test3"] == "test3"

    def test_dictionary_fromkeys(self):
        dictionary = SQLiteDict.fromkeys(["test", "test2"])
        assert dictionary["test"] is None
        assert dictionary["test2"] is None

    def test_dictionary_copy(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        copy = dictionary.copy()
        assert copy["test"] == "test"
        assert copy["test2"] == "test2"

    def test_dictionary_get(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert dictionary.get("test") == "test"
        assert dictionary.get("test2") == "test2"
        assert dictionary.get("test3") is None

    def test_dictionary_setdefault(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        assert dictionary.setdefault("test3", "test3") == "test3"
        assert dictionary["test3"] == "test3"
        assert dictionary.setdefault("test3", "test4") == "test3"
        assert dictionary["test3"] == "test3"

    def test_iterate_over_dict(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        for key, value in dictionary.items():
            assert key in ["test", "test2"]
            assert value in ["test", "test2"]
