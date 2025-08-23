"""create users and access tokens

Revision ID: c360318a95a5
Revises: 
Create Date: 2025-07-15 00:12:45.515406

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c360318a95a5'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'BVUsers',
        sa.Column('id', sa.UUID, primary_key=True, nullable=False, index=True),
        sa.Column('username', sa.String, unique=True, nullable=False, index=True),
        sa.Column('fast_login_secret', sa.String, nullable=False),
        sa.Column('is_active', sa.Boolean, nullable=False),
    )

    op.create_table(
        'BVUsersCredentials',
        sa.Column('user_id', sa.UUID, primary_key=True, nullable=False, index=True),
        sa.Column('password', sa.String, nullable=False),
    )
    with op.batch_alter_table('BVUsersCredentials', schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_user_id",
            "BVUsers",
            ["id"],
            ["user_id"],
            ondelete="CASCADE"
        )

    op.create_table(
        'BVSessions',
        sa.Column('user_id', sa.UUID, nullable=False),
        sa.Column('id', sa.UUID, primary_key=True, nullable=False, index=True),
        sa.Column('name', sa.String, nullable=True),
        sa.Column('device_type', sa.Enum('unknown', 'phone', 'computer'), nullable=False),
        sa.Column('created_at', sa.TIMESTAMP, nullable=False),
        sa.Column('last_used_at', sa.TIMESTAMP, nullable=False),
        sa.Column('refresh_token', sa.String, unique=True, nullable=False),
        sa.Column('is_active', sa.Boolean, nullable=False),
    )
    with op.batch_alter_table('BVSessions', schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_user_id",
            "BVUsers",
            ["id"],
            ["user_id"],
            ondelete="CASCADE"
        )

    op.create_table(
        'BVSessionsApps',
        sa.Column('session_id', sa.UUID, nullable=False),
        sa.Column('id', sa.UUID, primary_key=True, nullable=False, index=True),
        sa.Column('name', sa.String, nullable=False),
        sa.Column('created_at', sa.TIMESTAMP, nullable=False),
        sa.Column('last_used_at', sa.TIMESTAMP, nullable=False),
        sa.Column('refresh_token', sa.String, unique=True, nullable=False),
        sa.Column('is_active', sa.Boolean, nullable=False),
    )
    with op.batch_alter_table('BVSessionsApps', schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_session_id",
            "BVSessions",
            ["id"],
            ["session_id"],
            ondelete="CASCADE"
        )

def downgrade() -> None:
    op.drop_table('BVUsers')
    op.drop_table('BVUsersPasswords')
    op.drop_table('BVSessions')
    op.drop_table('BVSessionsApps')
