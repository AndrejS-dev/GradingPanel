# Generated by Django 5.1.4 on 2024-12-31 11:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='student',
            name='timeout_until',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='student',
            name='uid',
            field=models.CharField(default='undefined', max_length=100, unique=True),
        ),
    ]
