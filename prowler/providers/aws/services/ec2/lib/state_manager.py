class state_manager:
    check_ids = set()

    @classmethod
    def set_failed(cls, check_id=None):
        if check_id is not None:
            cls.check_ids.add(check_id)

    @classmethod
    def is_failed(cls, check_id):
        return check_id in cls.check_ids
