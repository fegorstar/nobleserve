# Generated by Django 5.0.4 on 2024-05-09 14:54

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_remove_userprofile_user_and_more'),
        ('customers', '0002_profile_remove_targetsaving_user_and_more'),
    ]

    operations = [
        migrations.DeleteModel(
            name='UserProfile',
        ),
    ]
