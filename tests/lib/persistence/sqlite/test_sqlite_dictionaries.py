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

        # The reason for the noqa and why we have to check the values using "==" instead of "is" is because the SQLiteDict class
        # is not a dictionary and due to Python limitations we can't check the values using "is" because there is no way to override
        # any magic method to change the behavior of the "is" operator.
        assert dictionary["test"] == None  # noqa: E711
        assert dictionary["test2"] == None  # noqa: E711

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

    def test_sub_objects_list(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = [1, 2, 3]

        assert dictionary["test2"][0] == 1
        assert dictionary["test2"][1] == 2
        assert dictionary["test2"][2] == 3

    def test_sub_objects_list_referencies(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = [1, 2, 3]

        tmp = dictionary["test2"]
        tmp[0] = 10

        assert dictionary["test2"][0] == 10
        assert dictionary["test2"][1] == 2
        assert dictionary["test2"][2] == 3

    def test_sub_objects_dict(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = {"test": "test"}

        assert dictionary["test2"]["test"] == "test"

    def test_sub_objects_dict_referencies(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = {"sub-obj": "test", "sub-obj2": "test2"}

        tmp = dictionary["test2"]
        tmp["sub-obj"] = "test3"

        assert dictionary["test"] == "test"
        assert dictionary["test2"]["sub-obj"] == "test3"
        assert dictionary["test2"]["sub-obj2"] == "test2"

    def test_sub_objects_dict_referencies_nested_simple_objects(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = {
            "sub-obj": "test",
            "sub-obj2": [
                "test2",
                {
                    "sub-obj3": "test3"
                }
            ]
        }

        tmp = dictionary["test2"]
        tmp["sub-obj2"][1]["sub-obj3"] = "test4"

        assert dictionary["test"] == "test"
        assert dictionary["test2"]["sub-obj"] == "test"

        assert dictionary["test2"]["sub-obj2"][0] == "test2"
        assert dictionary["test2"]["sub-obj2"][1]["sub-obj3"] == "test3"

    def test_sub_objects_dict_referencies_nested_complex_objects(self):
        class ComplexObject:
            def __init__(self, value, sub_value):
                self.sub_value = sub_value
                self.value = value

        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = {
            "sub-obj": "test",
            "sub-obj2": [
                "test2",
                ComplexObject("test3", {
                    "sub-obj3": "test4",
                    "sub-obj4": [
                        "test5",
                        ComplexObject("test6", {
                            "sub-obj7": "test7"
                        })
                    ]
                })
            ]
        }

        tmp = dictionary["test2"]
        tmp["sub-obj2"][1].sub_value["sub-obj4"][1].sub_value["sub-obj7"] = "test8"

        assert dictionary["test"] == "test"
        assert dictionary["test2"]["sub-obj"] == "test"

        assert dictionary["test2"]["sub-obj2"][0] == "test2"
        assert dictionary["test2"]["sub-obj2"][1].value == "test3"
        assert dictionary["test2"]["sub-obj2"][1].sub_value["sub-obj3"] == "test4"
        assert dictionary["test2"]["sub-obj2"][1].sub_value["sub-obj4"][0] == "test5"
        assert dictionary["test2"]["sub-obj2"][1].sub_value["sub-obj4"][1].value == "test6"
        assert dictionary["test2"]["sub-obj2"][1].sub_value["sub-obj4"][1].sub_value["sub-obj7"] == "test7"

    def test_iterate_over_dict_and_modify_sub_objects(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        for key, value in dictionary.items():
            if key == "test2":
                dictionary[key] = "test3"
                break

        assert dictionary["test"] == "test"
        assert dictionary["test2"] == "test3"

    def test_iterate_over_dict_and_modify_sub_objects_complex(self):
        class ComplexObject:
            def __init__(self, value, sub_value):
                self.sub_value = sub_value
                self.value = value

        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = ComplexObject("test2", {
            "sub-obj3": "test3",
            "sub-obj4": [
                "test4",
                ComplexObject("test5", {
                    "sub-obj7": "test6"
                })
            ]
        })
        for key, value in dictionary.items():
            if key == "test2":
                dictionary[key] = ComplexObject("test7", {
                    "sub-obj3": "test8",
                    "sub-obj4": [
                        "test9",
                        ComplexObject("test10", {
                            "sub-obj7": "test11"
                        })
                    ]
                })
                break

        assert dictionary["test"] == "test"
        assert dictionary["test2"].value == "test7"
        assert dictionary["test2"].sub_value["sub-obj3"] == "test8"
        assert dictionary["test2"].sub_value["sub-obj4"][0] == "test9"
        assert dictionary["test2"].sub_value["sub-obj4"][1].value == "test10"
        assert dictionary["test2"].sub_value["sub-obj4"][1].sub_value["sub-obj7"] == "test11"

    def test_iterate_over_dict_values_and_modify_sub_objects(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        for value in dictionary.values():
            if value == "test2":
                dictionary["test2"] = "test3"
                break

        assert dictionary["test"] == "test"
        assert dictionary["test2"] == "test3"

    def test_iterate_over_dict_values_and_modify_sub_objects_complex(self):
        class ComplexObject:
            def __init__(self, value, sub_value):
                self.sub_value = sub_value
                self.value = value

        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = ComplexObject("test2", {
            "sub-obj3": "test3",
            "sub-obj4": [
                "test4",
                ComplexObject("test5", {
                    "sub-obj7": "test6"
                })
            ]
        })
        for value in dictionary.values():
            if value.__class__.__name__ == "Wrapper":
                dictionary["test2"] = ComplexObject("test7", {
                    "sub-obj3": "test8",
                    "sub-obj4": [
                        "test9",
                        ComplexObject("test10", {
                            "sub-obj7": "test11"
                        })
                    ]
                })
                break

        assert dictionary["test"] == "test"
        assert dictionary["test2"].value == "test7"
        assert dictionary["test2"].sub_value["sub-obj3"] == "test8"
        assert dictionary["test2"].sub_value["sub-obj4"][0] == "test9"
        assert dictionary["test2"].sub_value["sub-obj4"][1].value == "test10"
        assert dictionary["test2"].sub_value["sub-obj4"][1].sub_value["sub-obj7"] == "test11"

    def test_iterate_over_dict_keys_and_modify_sub_objects(self):
        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = "test2"
        for key in dictionary.keys():
            if key == "test2":
                dictionary["test2"] = "test3"
                break

        assert dictionary["test"] == "test"
        assert dictionary["test2"] == "test3"

    def test_iterate_over_dict_keys_and_modify_sub_objects_complex(self):
        class ComplexObject:
            def __init__(self, value, sub_value):
                self.sub_value = sub_value
                self.value = value

        dictionary = SQLiteDict()
        dictionary["test"] = "test"
        dictionary["test2"] = ComplexObject("test2", {
            "sub-obj3": "test3",
            "sub-obj4": [
                "test4",
                ComplexObject("test5", {
                    "sub-obj7": "test6"
                })
            ]
        })
        for key in dictionary.keys():
            if key == "test2":
                dictionary["test2"] = ComplexObject("test7", {
                    "sub-obj3": "test8",
                    "sub-obj4": [
                        "test9",
                        ComplexObject("test10", {
                            "sub-obj7": "test11"
                        })
                    ]
                })
                break

        assert dictionary["test"] == "test"
        assert dictionary["test2"].value == "test7"
        assert dictionary["test2"].sub_value["sub-obj3"] == "test8"
        assert dictionary["test2"].sub_value["sub-obj4"][0] == "test9"
        assert dictionary["test2"].sub_value["sub-obj4"][1].value == "test10"
        assert dictionary["test2"].sub_value["sub-obj4"][1].sub_value["sub-obj7"] == "test11"

    def test_iterate_over_dict_values_composed(self):
        class ComplexObject:
            def __init__(self, value, sub_value):
                self.sub_value = sub_value
                self.value = value

        dictionary_1 = SQLiteDict()
        dictionary_1["test"] = "test"
        dictionary_1["test2"] = ComplexObject("test2", "test3")

        dictionary_2 = SQLiteDict()
        dictionary_2["test"] = "test"
        dictionary_2["test2"] = ComplexObject("test2", "test3")

        for value in dictionary_1.values():
            if value.__class__.__name__ == "ComplexObject":
                dictionary_2["test2"] = value
                break

        assert dictionary_1["test"] == "test"
        assert dictionary_1["test2"].value == "test2"
        assert dictionary_1["test2"].sub_value == "test3"

        assert dictionary_2["test"] == "test"
        assert dictionary_2["test2"].value == "test2"
        assert dictionary_2["test2"].sub_value == "test3"
