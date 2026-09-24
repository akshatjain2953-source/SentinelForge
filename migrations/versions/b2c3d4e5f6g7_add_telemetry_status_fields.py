"""add telemetry status fields

Revision ID: b2c3d4e5f6g7
Revises: da7060530ddf
Create Date: 2025-01-15 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'b2c3d4e5f6g7'
down_revision = 'da7060530ddf'
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns
    op.add_column('telemetry_events', sa.Column('status', sa.String(length=20), nullable=True))
    op.add_column('telemetry_events', sa.Column('claim_count', sa.Integer(), nullable=False, server_default=sa.text('0')))

    # Migrate existing data: processed=True -> completed, processed=False -> pending
    # Use compatible boolean literals for both SQLite and PostgreSQL
    op.execute("UPDATE telemetry_events SET status = 'completed' WHERE processed = 1")
    op.execute("UPDATE telemetry_events SET status = 'pending' WHERE processed = 0")

    # Set non-null constraints and defaults
    # Use dialect-appropriate default for updated_at
    from alembic import context
    dialect_name = context.get_context().dialect.name
    
    if dialect_name == 'sqlite':
        updated_at_default = "CURRENT_TIMESTAMP"
    else:
        updated_at_default = "NOW()"

    with op.batch_alter_table('telemetry_events', schema=None) as batch_op:
        batch_op.alter_column('status', nullable=False, server_default=sa.text("'pending'"))
        batch_op.alter_column('claim_count', nullable=False, server_default=sa.text('0'))
        # Drop old index
        batch_op.drop_index('ix_telemetry_received_processed')
        # Create new indexes
        batch_op.create_index('ix_telemetry_status', ['status'], unique=False)
        batch_op.create_index('ix_telemetry_status_updated', ['status', 'updated_at'], unique=False)
        batch_op.drop_column('processed')


def downgrade():
    # Add back processed column
    op.add_column('telemetry_events', sa.Column('processed', sa.Boolean(), nullable=False, server_default=sa.text('0')))

    # Migrate data back: completed -> True, pending/claimed/failed -> False
    op.execute("UPDATE telemetry_events SET processed = 1 WHERE status = 'completed'")
    op.execute("UPDATE telemetry_events SET processed = 0 WHERE status IN ('pending', 'claimed', 'failed')")

    with op.batch_alter_table('telemetry_events', schema=None) as batch_op:
        batch_op.drop_index('ix_telemetry_status_updated')
        batch_op.drop_index('ix_telemetry_status')
        # Restore old index
        batch_op.create_index('ix_telemetry_received_processed', ['received_at', 'processed'], unique=False)
        batch_op.drop_column('status')
        batch_op.drop_column('claim_count')