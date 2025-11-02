import pandas as pd
import pytest

from dashboard.lib.dropdowns import create_category_dropdown


class TestCategoryDropdown:
    def test_create_category_dropdown_with_categories(self):
        categories = ["All", "internet-exposed", "encryption", "logging"]
        dropdown = create_category_dropdown(categories)
        
        assert dropdown is not None
        assert dropdown.children[0].children == "Category:"
        assert dropdown.children[1].id == "category-filter"
        assert dropdown.children[1].value == ["All"]
        assert dropdown.children[1].multi is True
        assert dropdown.children[1].clearable is False

    def test_create_category_dropdown_empty_list(self):
        categories = []
        dropdown = create_category_dropdown(categories)
        
        assert dropdown is not None
        assert dropdown.children[1].id == "category-filter"

    def test_create_category_dropdown_single_category(self):
        categories = ["All", "internet-exposed"]
        dropdown = create_category_dropdown(categories)
        
        assert dropdown is not None
        assert len(dropdown.children[1].options) == 2


class TestCategoryFiltering:
    def test_filter_by_single_category(self):
        data = pd.DataFrame({
            "CATEGORIES": ["internet-exposed", "encryption", "internet-exposed, logging"],
            "STATUS": ["FAIL", "PASS", "FAIL"],
            "SEVERITY": ["high", "medium", "critical"]
        })
        
        filtered = data[
            data["CATEGORIES"].apply(
                lambda x: any(
                    cat.strip() in ["internet-exposed"]
                    for cat in str(x).split(",")
                    if str(x) != "nan"
                )
            )
        ]
        
        assert len(filtered) == 2
        assert "internet-exposed" in filtered.iloc[0]["CATEGORIES"]

    def test_filter_by_multiple_categories(self):
        data = pd.DataFrame({
            "CATEGORIES": ["internet-exposed", "encryption", "logging", "internet-exposed, encryption"],
            "STATUS": ["FAIL", "PASS", "FAIL", "FAIL"]
        })
        
        filtered = data[
            data["CATEGORIES"].apply(
                lambda x: any(
                    cat.strip() in ["internet-exposed", "encryption"]
                    for cat in str(x).split(",")
                    if str(x) != "nan"
                )
            )
        ]
        
        assert len(filtered) == 3

    def test_filter_with_nan_categories(self):
        data = pd.DataFrame({
            "CATEGORIES": ["internet-exposed", None, "encryption"],
            "STATUS": ["FAIL", "PASS", "FAIL"]
        })
        
        filtered = data[
            data["CATEGORIES"].apply(
                lambda x: any(
                    cat.strip() in ["internet-exposed"]
                    for cat in str(x).split(",")
                    if str(x) != "nan"
                )
            )
        ]
        
        assert len(filtered) == 1

    def test_extract_categories_from_csv_format(self):
        data = pd.DataFrame({
            "CATEGORIES": [
                "internet-exposed | encryption",
                "logging",
                "internet-exposed | logging | encryption"
            ]
        })
        
        categories = []
        for cat_list in data["CATEGORIES"].dropna().unique():
            if cat_list and str(cat_list) != "nan":
                for cat in str(cat_list).split("|"):
                    cat = cat.strip()
                    if cat and cat not in categories:
                        categories.append(cat)
        
        assert "internet-exposed" in categories
        assert "encryption" in categories
        assert "logging" in categories
        assert len(categories) == 3

    def test_category_filter_all_selection(self):
        category_values = ["All"]
        
        if category_values == ["All"]:
            updated_category_values = None
        else:
            updated_category_values = category_values
        
        assert updated_category_values is None

    def test_category_filter_specific_selection(self):
        category_values = ["internet-exposed", "encryption"]
        
        if category_values == ["All"]:
            updated_category_values = None
        else:
            updated_category_values = category_values
        
        assert updated_category_values == ["internet-exposed", "encryption"]

    def test_category_filter_with_all_and_others(self):
        category_values = ["All", "internet-exposed"]
        
        if "All" in category_values and len(category_values) > 1:
            category_values.remove("All")
            updated_category_values = category_values
        else:
            updated_category_values = category_values
        
        assert "All" not in updated_category_values
        assert "internet-exposed" in updated_category_values
