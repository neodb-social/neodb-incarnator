import io

import blurhash
import httpx
from django.conf import settings
from django.core.files import File
from django.core.files.base import ContentFile
from PIL import Image, ImageOps


class ImageFile(File):
    image: Image


def resize_image(
    image: File,
    *,
    size: tuple[int, int],
    cover=True,
    keep_format=False,
) -> ImageFile:
    """
    Resizes an image to fit insize the given size (cropping one dimension
    to fit if needed)
    """
    with Image.open(image) as img:
        try:
            # Take any orientation EXIF data, apply it, and strip the
            # orientation data from the new image.
            img = ImageOps.exif_transpose(img)
        except Exception:  # noqa
            # exif_transpose can crash with different errors depending on
            # the EXIF keys. Just ignore them all, better to have a rotated
            # image than no image.
            pass

        if cover:
            resized_image = ImageOps.fit(img, size, method=Image.Resampling.BILINEAR)
        else:
            resized_image = img.copy()
            resized_image.thumbnail(size, resample=Image.Resampling.BILINEAR)
        new_image_bytes = io.BytesIO()
        if keep_format:
            resized_image.save(new_image_bytes, format=img.format)
            file = ImageFile(new_image_bytes)
        else:
            resized_image.save(new_image_bytes, format="webp", save_all=True)
            file = ImageFile(new_image_bytes, name="image.webp")
        file.image = resized_image
        return file


def blurhash_image(file) -> str:
    """
    Returns the blurhash for an image
    """
    return blurhash.encode(file, 4, 4)


def get_video_dimensions(file) -> tuple[int, int] | None:
    """
    Extract width and height from an MP4/MOV file by parsing the tkhd box.
    Returns (width, height) or None if parsing fails.
    """
    import struct

    try:
        file.seek(0)
        data = file.read(64 * 1024)  # read first 64KB, enough for headers
        file.seek(0)
        pos = 0
        while pos < len(data) - 8:
            size = struct.unpack(">I", data[pos : pos + 4])[0]
            box_type = data[pos + 4 : pos + 8]
            if size < 8:
                break
            if box_type in (b"moov", b"trak"):
                # container boxes: descend into children
                pos += 8
                continue
            if box_type == b"tkhd":
                # tkhd layout (version 0):
                #   ver+flags(4) creation(4) modification(4) track_id(4)
                #   reserved(4) duration(4) reserved(8) layer(2)
                #   alt_group(2) volume(2) reserved(2) matrix(36)
                #   width(4, fixed 16.16) height(4, fixed 16.16)
                h_start = pos + 8
                version = data[h_start]
                if version == 0:
                    w_off = h_start + 76
                elif version == 1:
                    # v1 has 8-byte creation/modification/duration
                    w_off = h_start + 88
                else:
                    return None
                w = struct.unpack(">I", data[w_off : w_off + 4])[0] >> 16
                h = struct.unpack(">I", data[w_off + 4 : w_off + 8])[0] >> 16
                if w > 0 and h > 0:
                    return w, h
            pos += size
    except Exception:
        pass
    return None


def get_remote_file(
    url: str,
    *,
    timeout: float = settings.SETUP.REMOTE_TIMEOUT,
    max_size: int | None = None,
) -> tuple[File | None, str | None]:
    """
    Download a URL and return the File and content-type.
    """
    headers = {
        "User-Agent": settings.TAKAHE_USER_AGENT,
    }

    with httpx.Client(headers=headers) as client:
        with client.stream(
            "GET", url, timeout=timeout, follow_redirects=True
        ) as stream:
            allow_download = max_size is None
            if max_size:
                try:
                    content_length = int(stream.headers["content-length"])
                    allow_download = content_length <= max_size
                except (KeyError, TypeError):
                    pass
            if allow_download:
                file = ContentFile(stream.read(), name=url)
                return file, stream.headers.get(
                    "content-type", "application/octet-stream"
                )

    return None, None
