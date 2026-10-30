from django.db import connection
from django.test.utils import CaptureQueriesContext

from .....product.models import Category
from ....tests.utils import get_graphql_content

QUERY = """
query CategoryProductCounts {
  categories(first: 10) {
    edges { node { id products(first: 1) { totalCount } } }
  }
}
"""


def default_channel_queries(captured):
    return [
        q["sql"]
        for q in captured
        if 'FROM "channel_channel"' in q["sql"]
        and (
            "LIMIT 21" in q["sql"] or 'WHERE "channel_channel"."is_active"' in q["sql"]
        )
    ]


def test_nested_category_queries_reuse_default_only_within_the_request(
    api_client, product, channel_USD, channel_PLN
):
    # given: three nested resolvers need the sole active default channel.
    Category.objects.create(name="Empty one", slug="empty-one")
    Category.objects.create(name="Empty two", slug="empty-two")
    channel_PLN.is_active = False
    channel_PLN.save(update_fields=["is_active"])

    # when
    with CaptureQueriesContext(connection) as captured:
        response = api_client.post_graphql(QUERY)
    data = get_graphql_content(response)["data"]["categories"]["edges"]

    # then: one default lookup (get + active fallback), not one per category.
    assert len(default_channel_queries(captured)) == 2
    assert sorted(e["node"]["products"]["totalCount"] for e in data) == [0, 0, 1]

    # A subsequent request must see the newly ambiguous default immediately.
    channel_PLN.is_active = True
    channel_PLN.save(update_fields=["is_active"])
    with CaptureQueriesContext(connection) as captured:
        response = api_client.post_graphql(QUERY)
    content = response.json()
    assert len(default_channel_queries(captured)) == 2
    assert len(content["errors"]) == 3
    assert [e["message"] for e in content["errors"]] == [
        "More than one channel exists. Specify which channel to use."
    ] * 3
    assert [e["path"] for e in content["errors"]] == [
        ["categories", "edges", i, "node", "products"] for i in range(3)
    ]
