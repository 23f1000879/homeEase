"""Add rejection fields to service request

Revision ID: add_rejection_fields
Revises: previous_revision
Create Date: 2024-01-20
"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    # Add new columns to service_request table
    op.add_column('service_request', sa.Column('reject_reason', sa.String(50), nullable=True))
    op.add_column('service_request', sa.Column('reject_comment', sa.Text, nullable=True))
    op.add_column('service_request', sa.Column('rejected_at', sa.DateTime, nullable=True))

def downgrade():
    # Remove columns if needed to rollback
    op.drop_column('service_request', 'reject_reason')
    op.drop_column('service_request', 'reject_comment')
    op.drop_column('service_request', 'rejected_at') 