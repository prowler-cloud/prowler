"""Tests for the Prowler Cloud promo tour logic and layout."""

from dashboard.lib import cloud_promo as cp


class TestNextTourState:
    total = len(cp.TOUR_SLIDES)

    def test_trigger_opens_at_first_slide(self):
        assert cp.next_tour_state(cp.TRIGGER_ID, False, 3, self.total) == (True, 0)

    def test_close_keeps_index_and_closes(self):
        assert cp.next_tour_state(cp.CLOSE_ID, True, 2, self.total) == (False, 2)

    def test_backdrop_closes(self):
        assert cp.next_tour_state(cp.BACKDROP_ID, True, 1, self.total) == (False, 1)

    def test_next_advances_and_wraps(self):
        assert cp.next_tour_state(cp.NEXT_ID, True, 0, self.total) == (True, 1)
        assert cp.next_tour_state(cp.NEXT_ID, True, self.total - 1, self.total) == (
            True,
            0,
        )

    def test_prev_goes_back_and_wraps(self):
        assert cp.next_tour_state(cp.PREV_ID, True, 1, self.total) == (True, 0)
        assert cp.next_tour_state(cp.PREV_ID, True, 0, self.total) == (
            True,
            self.total - 1,
        )

    def test_unknown_trigger_is_noop(self):
        assert cp.next_tour_state("whatever", True, 2, self.total) == (True, 2)

    def test_empty_tour_stays_closed(self):
        assert cp.next_tour_state(cp.NEXT_ID, True, 0, 0) == (False, 0)


class TestSlides:
    def test_every_slide_has_image_and_copy(self):
        for slide in cp.TOUR_SLIDES:
            assert slide["image"].startswith("/assets/images/cloud/")
            assert slide["title"]
            assert slide["text"]
            assert slide["eyebrow"]

    def test_exactly_one_closing_cta(self):
        with_cta = [s for s in cp.TOUR_SLIDES if s.get("cta")]
        assert len(with_cta) == 1
        assert with_cta[0] is cp.TOUR_SLIDES[-1]


class TestLayout:
    def test_card_uses_trigger_id(self):
        card = cp.cloud_promo_card()
        # The clickable element carries the trigger id used by the callback.
        ids = _collect_ids(card)
        assert cp.TRIGGER_ID in ids

    def test_modal_exposes_stores_and_controls(self):
        modal = cp.cloud_tour_modal()
        ids = _collect_ids(modal)
        for expected in (
            cp.OVERLAY_ID,
            cp.OPEN_STORE_ID,
            cp.INDEX_STORE_ID,
            cp.CLOSE_ID,
            cp.BACKDROP_ID,
            cp.PREV_ID,
            cp.NEXT_ID,
            "cloud-tour-image",
        ):
            assert expected in ids


def _collect_ids(component):
    """Walk a Dash component tree collecting every string id."""
    ids = []

    def visit(node):
        comp_id = getattr(node, "id", None)
        if isinstance(comp_id, str):
            ids.append(comp_id)
        children = getattr(node, "children", None)
        if children is None:
            return
        if isinstance(children, (list, tuple)):
            for child in children:
                visit(child)
        else:
            visit(children)

    visit(component)
    return ids
