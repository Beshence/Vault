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
        'user',
        sa.Column('id', sa.UUID, primary_key=True, nullable=False),
        sa.Column('username', sa.String(320), nullable=False),
        sa.Column('hashed_password', sa.String(1024), nullable=False),
        sa.Column('is_active', sa.Boolean, nullable=False),
        sa.Column('is_superuser', sa.Boolean, nullable=False),
    )
    op.create_table(
        'accesstoken',
        sa.Column('user_id', sa.UUID, nullable=False),
        sa.Column('token', sa.String(171), primary_key=True, nullable=False),
        sa.Column('created_at', sa.TIMESTAMP, nullable=False)
    )
    with op.batch_alter_table('accesstoken', schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_user_id",
            "user",
            ["user_id"],
            ["id"],
            ondelete="CASCADE"
        )


def downgrade() -> None:
    op.drop_table('user')
    op.drop_table('accesstoken')
