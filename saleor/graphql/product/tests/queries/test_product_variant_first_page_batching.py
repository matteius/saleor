import graphene
import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from .....product.models import (
    Collection,
    CollectionChannelListing,
    ProductVariant,
    ProductVariantChannelListing,
)
from ....tests.utils import get_graphql_content

QUERY = """
query CollectionVariants($id: ID!, $channel: String!, $first: Int!) {
  collection(id: $id, channel: $channel) {
    products(first: 10) {
      edges { node {
        id
        productVariants(first: $first) {
          totalCount
          pageInfo { hasNextPage hasPreviousPage endCursor }
          edges { cursor node { id } }
        }
      } }
    }
  }
}
"""
NEXT_PAGE = """
query ProductVariants($id: ID!, $channel: String!, $after: String!) {
  product(id: $id, channel: $channel) {
    productVariants(first: 2, after: $after) {
      totalCount
      pageInfo { hasNextPage hasPreviousPage }
      edges { node { id } }
    }
  }
}
"""


@pytest.mark.parametrize("product_count", [2, 3])
def test_collection_batches_bounded_variant_pages_and_preserves_keyset_cursor(
    api_client, product_list, channel_USD, product_count
):
    # given: every product has three variants tied on nullable ordering fields.
    products = product_list[:product_count]
    collection = Collection.objects.create(
        name="Synthetic collection", slug="synthetic"
    )
    collection.products.add(*products)
    CollectionChannelListing.objects.create(
        collection=collection, channel=channel_USD, is_published=True
    )
    expected = {}
    for product in products:
        product.variants.update(sku=None, sort_order=None)
        extra = ProductVariant.objects.bulk_create(
            [ProductVariant(product=product, name=f"Variant {i}") for i in range(2)]
        )
        ProductVariantChannelListing.objects.bulk_create(
            [
                ProductVariantChannelListing(
                    variant=v,
                    channel=channel_USD,
                    currency=channel_USD.currency_code,
                    price_amount=10,
                    is_available_for_purchase=True,
                )
                for v in extra
            ]
        )
        expected[graphene.Node.to_global_id("Product", product.pk)] = [
            graphene.Node.to_global_id("ProductVariant", pk)
            for pk in product.variants.order_by("pk").values_list("pk", flat=True)
        ]
    variables = {
        "id": graphene.Node.to_global_id("Collection", collection.pk),
        "channel": channel_USD.slug,
        "first": 2,
    }

    # when: the real nested connection resolves every collection product.
    with CaptureQueriesContext(connection) as captured:
        response = api_client.post_graphql(QUERY, variables)
    products_data = get_graphql_content(response)["data"]["collection"]["products"][
        "edges"
    ]

    # then: one bounded window query replaces per-product SELECT and COUNT.
    windows = [q["sql"] for q in captured if "ROW_NUMBER() OVER" in q["sql"]]
    assert len(windows) == 1
    counts = [
        q["sql"]
        for q in captured
        if q["sql"].startswith("SELECT COUNT(*)")
        and 'FROM "product_productvariant"' in q["sql"]
    ]
    assert len(counts) == 0
    assert len(products_data) == product_count
    for edge in products_data:
        product = edge["node"]
        page = product["productVariants"]
        assert page["totalCount"] == 3
        assert [e["node"]["id"] for e in page["edges"]] == expected[product["id"]][:2]
        assert page["pageInfo"]["hasNextPage"] is True
        assert page["pageInfo"]["hasPreviousPage"] is False
        response = api_client.post_graphql(
            NEXT_PAGE,
            {
                "id": product["id"],
                "channel": channel_USD.slug,
                "after": page["pageInfo"]["endCursor"],
            },
        )
        next_page = get_graphql_content(response)["data"]["product"]["productVariants"]
        assert next_page["totalCount"] == 3
        assert [e["node"]["id"] for e in next_page["edges"]] == expected[product["id"]][
            2:
        ]
        assert next_page["pageInfo"] == {"hasNextPage": False, "hasPreviousPage": True}
