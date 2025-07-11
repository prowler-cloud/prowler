# Generated manually for API Key model with multi-tenancy

from django.db import migrations, models
import django.db.models.deletion
import uuid
from api.db_utils import generate_random_token
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0033_samltoken"),
    ]

    operations = [
        migrations.CreateModel(
            name='APIKey',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255, validators=[django.core.validators.MinLengthValidator(3)], help_text='Human-readable name to identify the API key')),
                ('key_hash', models.CharField(max_length=255, unique=True, help_text='Django password hash of the API key')),
                ('prefix', models.CharField(max_length=10, help_text='Prefix of the API key for identification')),
                ('expires_at', models.DateTimeField(blank=True, null=True, help_text='Expiration time. Null means no expiration.')),
                ('last_used_at', models.DateTimeField(blank=True, null=True, help_text='Last time this API key was used')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('revoked_at', models.DateTimeField(blank=True, null=True, help_text='Time when the key was revoked. Null means active.')),
                ('created_ip', models.GenericIPAddressField(blank=True, null=True, help_text='IP address from which the key was created')),
                ('last_used_ip', models.GenericIPAddressField(blank=True, null=True, help_text='IP address from which the key was last used')),
                ('tenant_id', models.UUIDField(help_text='Tenant ID for multi-tenancy support')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='api_keys', related_query_name='api_key', to='api.user')),
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
            index=models.Index(fields=['tenant_id', 'revoked_at'], name='api_keys_tenant_active_idx'),
        ),
        migrations.AddIndex(
            model_name='apikey',
            index=models.Index(fields=['created_by', 'revoked_at'], name='api_keys_user_active_idx'),
        ),
        # Enable RLS and create policy
        migrations.RunSQL(
            """
            ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
            CREATE POLICY rls_on_api_keys ON api_keys FOR ALL 
            USING (tenant_id = current_setting('row_level_security.tenant_id')::uuid);
            """,
            reverse_sql="""
            DROP POLICY IF EXISTS rls_on_api_keys ON api_keys;
            ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;
            """
        ),
    ] 