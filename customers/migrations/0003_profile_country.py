# Generated by Django 5.0.4 on 2024-05-14 14:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('customers', '0002_profile_remove_targetsaving_user_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='country',
            field=models.CharField(default='', max_length=250),
        ),
    ]