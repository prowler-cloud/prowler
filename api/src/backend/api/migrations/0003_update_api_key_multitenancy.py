# Generated manually for API Key model multi-tenancy updates

from django.db import migrations, models
import django.db.models.deletion
import uuid
from api.rls import RowLevelSecurityConstraint


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_add_api_key_model'),
    ]

    operations = [
        # Add tenant_id field first
        migrations.AddField(
            model_name='apikey',
            name='tenant_id',
            field=models.UUIDField(null=True),
        ),
        
        # Rename user to created_by
        migrations.RenameField(
            model_name='apikey',
            old_name='user',
            new_name='created_by',
        ),
        
        # Update indexes
        migrations.RemoveIndex(
            model_name='apikey',
            name='api_keys_user_active_idx',
        ),
        migrations.AddIndex(
            model_name='apikey',
            index=models.Index(fields=['tenant_id', 'revoked_at'], name='api_keys_tenant_active_idx'),
        ),
        migrations.AddIndex(
            model_name='apikey',
            index=models.Index(fields=['created_by', 'revoked_at'], name='api_keys_user_active_idx'),
        ),
        
        # Remove old constraint
        migrations.RunSQL(
            "ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS statements_on_api_keys;",
            reverse_sql="-- No reverse operation"
        ),
        
        # Add RLS constraint
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
        
        # Make tenant_id not null after the policy is in place
        migrations.AlterField(
            model_name='apikey',
            name='tenant_id',
            field=models.UUIDField(),
        ),
    ] 