"""Added User Model

Revision ID: 8609f245b67c
Revises:
Create Date: 2021-06-06 13:59:22.599137

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "8609f245b67c"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("email", sa.String(length=2555), nullable=False),
        sa.Column("password_hash", sa.String(length=100), nullable=True),
        sa.Column("registered_on", sa.DateTime(), nullable=True),
        sa.Column("admin", sa.Boolean(), nullable=True),
        sa.Column("public_id", sa.String(length=36), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("public_id"),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("user")
    # ### end Alembic commands ###
