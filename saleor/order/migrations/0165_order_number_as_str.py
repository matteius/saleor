# Generated by Django 3.2.18 on 2023-05-08 19:05

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("order", "0164_auto_20230329_1200"),
    ]

    operations = [
        migrations.AddField(
            model_name="order",
            name="number_as_str",
            field=models.CharField(max_length=64, null=True, unique=True),
        ),
    ]
