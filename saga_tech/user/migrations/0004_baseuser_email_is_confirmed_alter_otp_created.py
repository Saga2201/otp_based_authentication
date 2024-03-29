# Generated by Django 5.0.1 on 2024-01-18 07:44

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0003_alter_otp_created'),
    ]

    operations = [
        migrations.AddField(
            model_name='baseuser',
            name='email_is_confirmed',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='otp',
            name='created',
            field=models.DateTimeField(default=datetime.datetime(2024, 1, 18, 7, 44, 19, 827504)),
        ),
    ]
