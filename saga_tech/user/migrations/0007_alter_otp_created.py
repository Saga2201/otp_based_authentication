# Generated by Django 5.0.1 on 2024-01-19 18:09

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0006_alter_otp_created'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='created',
            field=models.DateTimeField(default=datetime.datetime(2024, 1, 19, 18, 9, 10, 988148)),
        ),
    ]
