from datetime import timedelta

from django.db.models import Count
from django.http import HttpRequest
from django.utils import timezone

from activities.models import Hashtag, Post
from api import schemas
from api.decorators import scope_required
from hatchway import api_view


@scope_required("read")
@api_view.get
def trends_tags(
    request: HttpRequest,
    limit: int = 10,
    offset: int | None = None,
) -> list[schemas.Tag]:
    if limit > 40:
        limit = 40
    if offset is None or offset < 0:
        offset = 0
    if offset + limit > 100:
        offset = 100 - limit
    return schemas.Tag.map_from_hashtags(
        Hashtag.popular(limit=limit, offset=offset),
        domain=request.domain,
        identity=request.identity,
    )


@scope_required("read")
@api_view.get
def trends_statuses(
    request: HttpRequest,
    limit: int = 10,
    offset: int | None = None,
) -> list[schemas.Status]:
    if limit > 40:
        limit = 40
    if offset is None or offset < 0:
        offset = 0
    if offset + limit > 100:
        offset = 100 - limit
    since = timezone.now().date() - timedelta(days=30)
    posts = (
        Post.objects.not_hidden()
        .public()
        .filter(published__gte=since)
        .annotate(num_interactions=Count("interactions"))
        .filter(num_interactions__gt=2)
        .order_by("-num_interactions", "-published")[offset : offset + limit]
    )
    return schemas.Status.map_from_post(list(posts), request.identity)


from hatchway import Schema, Field
from django.core.cache import cache


class Link(Schema):
    type: str = "link"
    title: str
    description: str
    url: str
    image: str
    html: str = ""
    width: int = Field(default=400)
    height: int = Field(default=225)
    author_name: str = ""
    author_url: str = ""
    provider_name: str = ""
    provider_url: str = ""
    blurhash: str = ""
    embed_url: str = ""
    history: list = []


@scope_required("read")
@api_view.get
def trends_links(
    request: HttpRequest,
    limit: int = 10,
    offset: int | None = None,
) -> list[Link]:
    if limit > 40:
        limit = 40
    if offset is None or offset < 0:
        offset = 0
    if offset + limit > 100:
        offset = 100 - limit
    links = cache.get("trends_links", [])
    return links[offset : offset + limit]
