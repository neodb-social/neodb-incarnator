import pytest

from activities.models import Post
from users.models import InboxMessage


@pytest.mark.django_db
def test_to_ap_includes_replies_collection(identity):
    """Local posts should include a replies Collection in their AP representation."""
    post = Post.objects.create(
        author=identity,
        content="Hello world",
        local=True,
        visibility=Post.Visibilities.public,
    )
    post.object_uri = post.urls.object_uri
    post.url = post.absolute_object_uri()
    post.save()

    ap = post.to_ap()
    assert "replies" in ap
    assert ap["replies"]["type"] == "Collection"
    assert ap["replies"]["id"] == post.object_uri + "replies/"
    assert "first" in ap["replies"]
    first_page = ap["replies"]["first"]
    assert first_page["type"] == "CollectionPage"
    assert first_page["partOf"] == post.object_uri + "replies/"


@pytest.mark.django_db
def test_to_ap_replies_includes_reply_uris(identity):
    """The replies collection should include URIs of public replies."""
    parent = Post.objects.create(
        author=identity,
        content="Parent post",
        local=True,
        visibility=Post.Visibilities.public,
    )
    parent.object_uri = parent.urls.object_uri
    parent.url = parent.absolute_object_uri()
    parent.save()

    reply = Post.objects.create(
        author=identity,
        content="A reply",
        local=True,
        in_reply_to=parent.object_uri,
        visibility=Post.Visibilities.public,
    )
    reply.object_uri = reply.urls.object_uri
    reply.save()

    ap = parent.to_ap()
    first_page = ap["replies"]["first"]
    assert reply.object_uri in first_page["items"]


@pytest.mark.django_db
def test_ensure_object_uri_respects_depth_limit():
    """ensure_object_uri should not create a FetchPost message when depth exceeds limit."""
    initial_count = InboxMessage.objects.count()

    # Depth within limit should create a message
    Post.ensure_object_uri(
        "https://remote.test/posts/shallow", reason="test", depth=0
    )
    assert InboxMessage.objects.count() == initial_count + 1

    # Depth at MAX_ANCESTOR_FETCH_DEPTH - 1 should still work
    Post.ensure_object_uri(
        "https://remote.test/posts/at-limit",
        reason="test",
        depth=Post.MAX_ANCESTOR_FETCH_DEPTH - 1,
    )
    assert InboxMessage.objects.count() == initial_count + 2

    # Depth at MAX_ANCESTOR_FETCH_DEPTH should NOT create a message
    Post.ensure_object_uri(
        "https://remote.test/posts/too-deep",
        reason="test",
        depth=Post.MAX_ANCESTOR_FETCH_DEPTH,
    )
    assert InboxMessage.objects.count() == initial_count + 2  # unchanged


@pytest.mark.django_db
def test_fetch_post_message_includes_depth():
    """FetchPost internal messages should carry a depth field."""
    Post.ensure_object_uri(
        "https://remote.test/posts/depth-test", reason="test", depth=3
    )
    msg = InboxMessage.objects.order_by("-id").first()
    assert msg.message["object"]["depth"] == 3
