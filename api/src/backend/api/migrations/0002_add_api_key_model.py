# Generated manually for API Key model

from django.db import migrations, models
import django.db.models.deletion
import uuid
from api.db_utils import generate_random_token
import django.core.validators
from api.rls import BaseSecurityConstraint


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='APIKey',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255, validators=[django.core.validators.MinLengthValidator(3)], help_text='Human-readable name to identify the API key')),
                ('key_hash', models.CharField(max_length=128, unique=True, help_text='SHA-256 hash of the API key')),
                ('prefix', models.CharField(max_length=10, help_text='Prefix of the API key for identification')),
                ('expires_at', models.DateTimeField(blank=True, null=True, help_text='Expiration time. Null means no expiration.')),
                ('last_used_at', models.DateTimeField(blank=True, null=True, help_text='Last time this API key was used')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('revoked_at', models.DateTimeField(blank=True, null=True, help_text='Time when the key was revoked. Null means active.')),
                ('created_ip', models.GenericIPAddressField(blank=True, null=True, help_text='IP address from which the key was created')),
                ('last_used_ip', models.GenericIPAddressField(blank=True, null=True, help_text='IP address from which the key was last used')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='api_keys', related_query_name='api_key', to='api.user')),
            ],
            options={
                'db_table': 'api_keys',
            },
        ),
        migrations.AddIndex(
            model_name='apikey',
            index=models.Index(fields=['prefix'], name='api_keys_prefix_idx'),
        ),
        migrations.AddIndex(
            model_name='apikey',
            index=models.Index(fields=['user', 'revoked_at'], name='api_keys_user_active_idx'),
        ),
        migrations.AddConstraint(
            model_name='apikey',
            constraint=BaseSecurityConstraint(
                name='statements_on_apikey',
                statements=['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
            ),
        ),
    ] 