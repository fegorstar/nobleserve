# Generated by Django 5.0.4 on 2024-05-29 03:53

import shortuuid.django_fields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('customers', '0010_alter_corporateloan_has_documents_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='corporateloan',
            name='transaction_id',
            field=shortuuid.django_fields.ShortUUIDField(alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+!,~-%*£', length=12, max_length=40, prefix='NBL_'),
        ),
        migrations.AlterField(
            model_name='leasefinancing',
            name='transaction_id',
            field=shortuuid.django_fields.ShortUUIDField(alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+,~-&£', length=12, max_length=40, prefix='NBL_'),
        ),
        migrations.AlterField(
            model_name='targetsaving',
            name='transaction_id',
            field=shortuuid.django_fields.ShortUUIDField(alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+,~-&£', length=12, max_length=40, prefix='NBL_'),
        ),
    ]
