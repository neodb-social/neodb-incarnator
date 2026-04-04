import pytest

from activities.models import Post


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
