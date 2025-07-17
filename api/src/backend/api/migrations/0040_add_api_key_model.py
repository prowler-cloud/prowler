# Generated manually for API Key model and API Key Activity logging with multi-tenancy
# This migration creates API keys without user association and optional user in activity logging

from django.db import migrations, models
import django.db.models.deletion
import uuid
from uuid import uuid4
from api.db_utils import generate_random_token, DB_PROWLER_USER, POSTGRES_TENANT_VAR
import django.core.validators
import api.rls


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0039_resource_resources_failed_findings_idx"),
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
                ('tenant_id', models.UUIDField(help_text='Tenant ID for multi-tenancy support')),
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
            index=models.Index(fields=['tenant_id', 'prefix'], name='api_keys_tenant_prefix_idx'),
        ),
        # Add RLS constraint for api_keys
        migrations.AddConstraint(
            model_name='apikey',
            constraint=api.rls.RowLevelSecurityConstraint(
                field='tenant_id',
                name='rls_on_apikey',
                statements=['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
            ),
        ),
        
        # Create APIKeyActivity model for comprehensive audit logging
        migrations.CreateModel(
            name='APIKeyActivity',
            fields=[
                ('id', models.UUIDField(default=uuid4, editable=False, primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField(auto_now_add=True, db_index=True, editable=False)),
                ('method', models.CharField(max_length=10, help_text='HTTP method (GET, POST, etc.)')),
                ('endpoint', models.CharField(max_length=500, help_text='API endpoint that was accessed')),
                ('source_ip', models.GenericIPAddressField(db_index=True, help_text='Source IP address of the request')),
                ('user_agent', models.TextField(blank=True, null=True, help_text='User agent string from the request')),
                ('status_code', models.IntegerField(help_text='HTTP status code of the response')),
                ('response_size', models.IntegerField(blank=True, null=True, help_text='Size of the response in bytes')),
                ('duration_ms', models.IntegerField(blank=True, null=True, help_text='Request duration in milliseconds')),
                ('query_params', models.JSONField(blank=True, default=dict, help_text='Query parameters from the request (for audit purposes)')),
                ('tenant_id', models.UUIDField(help_text='Tenant ID for multi-tenancy support')),
                ('api_key', models.ForeignKey(help_text='API key that was used for this request', on_delete=django.db.models.deletion.CASCADE, related_name='activity_logs', related_query_name='activity_log', to='api.apikey')),
                ('user', models.ForeignKey(blank=True, null=True, help_text='User who owns the API key (optional for API key authentication)', on_delete=django.db.models.deletion.SET_NULL, related_name='api_key_activities', related_query_name='api_key_activity', to='api.user')),
            ],
            options={
                'db_table': 'api_key_activities',
                'ordering': ['-timestamp'],
            },
        ),
        
        # Add indexes for APIKeyActivity performance optimization
        migrations.AddIndex(
            model_name='apikeyactivity',
            index=models.Index(fields=['api_key', '-timestamp'], name='api_key_activity_key_time_idx'),
        ),
        migrations.AddIndex(
            model_name='apikeyactivity',
            index=models.Index(fields=['tenant_id', '-timestamp'], name='api_key_activity_tenant_time_idx'),
        ),
        migrations.AddIndex(
            model_name='apikeyactivity',
            index=models.Index(fields=['source_ip', '-timestamp'], name='api_key_activity_ip_time_idx'),
        ),
        migrations.AddIndex(
            model_name='apikeyactivity',
            index=models.Index(fields=['endpoint', '-timestamp'], name='api_key_activity_endpoint_time_idx'),
        ),
        migrations.AddIndex(
            model_name='apikeyactivity',
            index=models.Index(fields=['status_code', '-timestamp'], name='api_key_activity_status_time_idx'),
        ),
        migrations.AddIndex(
            model_name='apikeyactivity',
            index=models.Index(fields=['tenant_id', 'api_key', 'source_ip', '-timestamp'], name='api_key_activity_incident_idx'),
        ),
        
        # Add RLS constraint for api_key_activities
        migrations.AddConstraint(
            model_name='apikeyactivity',
            constraint=api.rls.RowLevelSecurityConstraint(
                field='tenant_id',
                name='rls_on_apikeyactivity',
                statements=['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
            ),
        ),
    ] 