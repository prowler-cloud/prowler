from prowler.lib.persistence.sqlite import SQLiteList


class Test_SqliteList:
    def test_create_list(self):
        lst = SQLiteList()
        lst.append("test")
        assert lst[0] == "test"

    def test_create_list_add_two_elements(self):
        lst = SQLiteList()
        lst.append("test1")
        lst.append("test2")
        assert lst[0] == "test1"
        assert lst[1] == "test2"

    def test_list_length(self):
        lst = SQLiteList()
        lst.append("test1")
        lst.append("test2")
        assert len(lst) == 2

    def test_list_extend(self):
        lst = SQLiteList()
        lst.extend(["test1", "test2", "test3"])
        assert len(lst) == 3
        assert lst[2] == "test3"

    def test_list_setitem(self):
        lst = SQLiteList()
        lst.append("test1")
        lst[0] = "updated"
        assert lst[0] == "updated"

    def test_list_delitem(self):
        lst = SQLiteList()
        lst.extend(["test1", "test2", "test3"])
        del lst[1]
        assert len(lst) == 2
        assert lst[1] == "test3"

    def test_list_iter(self):
        lst = SQLiteList()
        lst.extend(["test1", "test2", "test3"])
        items = [item for item in lst]
        assert items == ["test1", "test2", "test3"]

    def test_list_add(self):
        lst1 = SQLiteList()
        lst1.extend(["test1", "test2"])
        lst2 = SQLiteList()
        lst2.extend(["test3", "test4"])
        result = lst1 + lst2
        assert len(result) == 4
        assert result[2] == "test3"

    def test_list_iadd(self):
        lst = SQLiteList()
        lst.extend(["test1", "test2"])
        lst += ["test3", "test4"]
        assert len(lst) == 4
        assert lst[3] == "test4"

    def test_list_contains(self):
        lst = SQLiteList()
        lst.extend(["test1", "test2", "test3"])
        assert "test2" in lst
        assert "test4" not in lst

    def test_list_index_out_of_range(self):
        lst = SQLiteList()
        lst.append("test")
        try:
            _ = lst[1]
            assert False, "IndexError not raised"
        except IndexError:
            assert True

    def test_list_setitem_out_of_range(self):
        lst = SQLiteList()
        lst.append("test")
        try:
            lst[1] = "new"
            assert False, "IndexError not raised"
        except IndexError:
            assert True

    def test_list_delitem_out_of_range(self):
        lst = SQLiteList()
        lst.append("test")
        try:
            del lst[1]
            assert False, "IndexError not raised"
        except IndexError:
            assert True
