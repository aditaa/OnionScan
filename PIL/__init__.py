class UnidentifiedImageError(Exception):
    pass


class ImageModule:
    def open(self, *args, **kwargs):
        raise UnidentifiedImageError("image not found")


Image = ImageModule()
